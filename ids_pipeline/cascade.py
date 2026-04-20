"""Modbus IDS: window + per-packet Isolation Forest with optional time split and cascade alerts."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, List, Literal, Optional, Sequence, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

Contamination = Union[float, str]


def shannon_entropy(counts: np.ndarray) -> float:
    counts = counts.astype(float)
    s = counts.sum()
    if s <= 0:
        return 0.0
    p = counts / s
    p = p[p > 0]
    return float(-(p * np.log2(p)).sum())


def load_clean_csv(path: Path | str) -> pd.DataFrame:
    df = pd.read_csv(path)
    df["Time"] = pd.to_datetime(df["Time"], errors="coerce")
    df = df.dropna(subset=["Time"])
    df["Func"] = pd.to_numeric(df["Func"], errors="coerce")
    df["Unit_ID"] = pd.to_numeric(df["Unit_ID"], errors="coerce")
    df["Trans_ID"] = pd.to_numeric(df["Trans_ID"], errors="coerce")
    df["Type"] = df["Type"].astype(str)
    df["Dst IP"] = df["Dst IP"].astype(str)
    df["ts"] = df["Time"].astype("int64") / 1e9
    return df


def assign_window_index(df: pd.DataFrame, window_sec: float) -> tuple[pd.DataFrame, float]:
    """Sort by time, set t0 and integer window id ``w``."""
    out = df.sort_values("ts").reset_index(drop=True)
    t0 = float(out["ts"].min())
    out["w"] = ((out["ts"] - t0) // float(window_sec)).astype(int)
    return out, t0


def build_window_features(df: pd.DataFrame, window_sec: float, t0: float) -> pd.DataFrame:
    rows: List[dict[str, Any]] = []
    for w, g in df.groupby("w"):
        n_msgs = len(g)
        n_req = int((g["Type"] == "Request").sum())
        n_resp = int((g["Type"] == "Response").sum())
        func_counts = g["Func"].value_counts(dropna=True)
        n_unique_func = int(func_counts.shape[0])
        func_entropy = shannon_entropy(func_counts.values)
        n_unique_dst = int(g["Dst IP"].nunique())
        trans_counts = g["Trans_ID"].value_counts(dropna=True)
        trans_reuse_max = int(trans_counts.max()) if len(trans_counts) else 0
        trans_entropy = shannon_entropy(trans_counts.values) if len(trans_counts) else 0.0
        unit_counts = g["Unit_ID"].value_counts(dropna=True)
        n_unique_unit = int(unit_counts.shape[0])
        ts_sorted = np.sort(g["ts"].values)
        if len(ts_sorted) >= 2:
            iats = np.diff(ts_sorted)
            iat_mean = float(iats.mean())
            iat_std = float(iats.std())
            iat_p95 = float(np.percentile(iats, 95))
        else:
            iat_mean = 0.0
            iat_std = 0.0
            iat_p95 = 0.0
        row: dict[str, Any] = {
            "w": int(w),
            "t_start": float(w * window_sec + t0),
            "t_end": float((w + 1) * window_sec + t0),
            "n_msgs": n_msgs,
            "n_req": n_req,
            "n_resp": n_resp,
            "req_ratio": float(n_req / max(1, n_msgs)),
            "n_unique_func": n_unique_func,
            "func_entropy": func_entropy,
            "n_unique_unit": n_unique_unit,
            "n_unique_dst": n_unique_dst,
            "trans_reuse_max": trans_reuse_max,
            "trans_entropy": trans_entropy,
            "iat_mean": iat_mean,
            "iat_std": iat_std,
            "iat_p95": iat_p95,
        }
        for fc in [1, 2, 3, 4, 5, 6, 15, 16]:
            row[f"fc_{fc}_cnt"] = int((g["Func"] == fc).sum())
        rows.append(row)
    return pd.DataFrame(rows).sort_values("w").reset_index(drop=True)


def window_feature_columns(
    feat: pd.DataFrame, *, include_dst_context: bool, drop_src_identity: bool
) -> List[str]:
    _ = drop_src_identity  # reserved for future raw-identity drops
    cols = [c for c in feat.columns if c not in ("w", "t_start", "t_end")]
    if not include_dst_context:
        cols = [c for c in cols if c != "n_unique_dst"]
    return cols


def build_packet_table(df: pd.DataFrame, *, include_dst: bool) -> pd.DataFrame:
    pkt = df.sort_values("ts").reset_index(drop=True)
    pkt["iat_sec"] = pkt["ts"].diff().fillna(0.0).clip(lower=0.0)
    pkt["is_req"] = (pkt["Type"] == "Request").astype(np.int8)
    pkt["data_len"] = pkt["Data"].astype(str).str.len()
    if include_dst:
        pkt["dst_code"], _ = pd.factorize(pkt["Dst IP"], sort=True)
    return pkt


def packet_feature_columns(pkt: pd.DataFrame, *, include_dst: bool) -> List[str]:
    cols = ["Func", "Unit_ID", "Trans_ID", "is_req", "iat_sec", "data_len"]
    if include_dst and "dst_code" in pkt.columns:
        cols.append("dst_code")
    return cols


def _iso_to_epoch(s: Any) -> Optional[float]:
    if not s:
        return None
    return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()


def load_attack_intervals_epoch(path: Path) -> List[Tuple[float, float, str]]:
    pending: defaultdict[str, deque] = defaultdict(deque)
    out: List[Tuple[float, float, str]] = []
    if not path.exists():
        return out
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            o = json.loads(line)
            ev = o.get("event")
            ts = _iso_to_epoch(o.get("ts_iso"))
            if ts is None:
                continue
            aid = str(o.get("attack_id", ""))
            if ev == "episode_start" and aid:
                pending[aid].append(ts)
            elif ev == "episode_end" and aid:
                if not pending[aid]:
                    continue
                t0 = pending[aid].popleft()
                t1 = ts
                if t1 < t0:
                    t0, t1 = t1, t0
                out.append((t0, t1, aid))
    return out


def load_attack_intervals(paths: Sequence[Path]) -> List[Tuple[float, float, str]]:
    intervals: List[Tuple[float, float, str]] = []
    for p in paths:
        intervals.extend(load_attack_intervals_epoch(Path(p)))
    return intervals


def resolve_label_ts_offset(
    ts: np.ndarray,
    jsonl_paths: Sequence[Path],
    manual_offset_sec: Optional[float],
) -> tuple[float, List[Tuple[float, float, str]]]:
    """
    Load JSONL intervals and return ``(offset_sec, intervals)``.
    If ``manual_offset_sec`` is ``None``, pick offset via :func:`suggest_eval_ts_offset_sec`.
    """
    intervals = load_attack_intervals(jsonl_paths)
    if manual_offset_sec is not None:
        return float(manual_offset_sec), intervals
    off, _hits = suggest_eval_ts_offset_sec(ts, intervals)
    return float(off), intervals


def intervals_overlap(a0: float, a1: float, b0: float, b1: float) -> bool:
    return (a1 >= b0) and (b1 >= a0)


@dataclass
class CascadeConfig:
    window_sec: float = 10.0
    include_dst_context: bool = True
    drop_src_identity: bool = True
    win_contamination: Contamination = "auto"
    pkt_contamination: Contamination = 0.01
    n_estimators_win: int = 300
    n_estimators_pkt: int = 150
    packet_include_dst: bool = False
    """If set in (0, 1), fit scalers + forests only on data strictly before the time cut."""
    train_frac: Optional[float] = None
    # If True, fit IF only on traffic outside JSONL episode intervals (see fit_and_score).
    fit_benign_only: bool = False
    random_state: int = 42
    cascade_mode: Literal["and", "top_k"] = "top_k"
    cascade_top_k: int = 25


@dataclass
class CascadeResult:
    df: pd.DataFrame
    feat: pd.DataFrame
    pkt: pd.DataFrame
    t_cut: Optional[float]
    config: CascadeConfig
    """True when ``df``/``feat``/``pkt`` come from a scoring capture, not the fit capture."""
    separate_eval_corpus: bool = False


def _contam_arg(c: Contamination) -> Any:
    return c if c == "auto" else float(c)


def _time_cut(df: pd.DataFrame, train_frac: float) -> float:
    t_min = float(df["ts"].min())
    t_max = float(df["ts"].max())
    return t_min + float(train_frac) * (t_max - t_min)


def _train_isolation_forests(
    cfg: CascadeConfig,
    feat_fit: pd.DataFrame,
    pkt_fit: pd.DataFrame,
    win_cols: List[str],
    pkt_cols: List[str],
) -> tuple[StandardScaler, StandardScaler, IsolationForest, IsolationForest]:
    Xw = feat_fit[win_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    Xp = pkt_fit[pkt_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    scaler_w = StandardScaler()
    scaler_p = StandardScaler()
    Xwz = scaler_w.fit_transform(Xw)
    Xpz = scaler_p.fit_transform(Xp)
    if_win = IsolationForest(
        n_estimators=cfg.n_estimators_win,
        contamination=_contam_arg(cfg.win_contamination),
        random_state=cfg.random_state,
        n_jobs=-1,
    )
    if_pkt = IsolationForest(
        n_estimators=cfg.n_estimators_pkt,
        contamination=_contam_arg(cfg.pkt_contamination),
        random_state=cfg.random_state,
        n_jobs=-1,
    )
    if_win.fit(Xwz)
    if_pkt.fit(Xpz)
    return scaler_w, scaler_p, if_win, if_pkt


def _score_and_cascade(
    cfg: CascadeConfig,
    scaler_w: StandardScaler,
    scaler_p: StandardScaler,
    if_win: IsolationForest,
    if_pkt: IsolationForest,
    feat: pd.DataFrame,
    pkt: pd.DataFrame,
    df: pd.DataFrame,
    win_cols: List[str],
    pkt_cols: List[str],
) -> tuple[pd.DataFrame, pd.DataFrame]:
    Xw_all = feat[win_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    Xp_all = pkt[pkt_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    feat = feat.copy()
    pkt = pkt.copy()
    feat["if_score"] = if_win.decision_function(scaler_w.transform(Xw_all))
    feat["if_pred"] = if_win.predict(scaler_w.transform(Xw_all))
    pkt["pkt_if_score"] = if_pkt.decision_function(scaler_p.transform(Xp_all))
    pkt["pkt_if_pred"] = if_pkt.predict(scaler_p.transform(Xp_all))
    win_map = feat.set_index("w")[["if_score", "if_pred"]]
    pkt["win_if_score"] = pkt["w"].map(win_map["if_score"])
    pkt["win_if_pred"] = pkt["w"].map(win_map["if_pred"]).astype(np.int8)
    win_anom = pkt["win_if_pred"].values == -1
    if cfg.cascade_mode == "and":
        pkt["cascade_alert"] = win_anom & (pkt["pkt_if_pred"].values == -1)
    else:
        rk = pkt.groupby("w")["pkt_if_score"].rank(method="first", ascending=True)
        pkt["pkt_rank_anom_in_w"] = rk
        pkt["cascade_alert"] = win_anom & (rk <= float(cfg.cascade_top_k))
    pkt["cascade_alert"] = pkt["cascade_alert"].astype(bool)
    return feat, pkt


def _feat_pkt_fit_subset(
    df: pd.DataFrame,
    feat: pd.DataFrame,
    pkt: pd.DataFrame,
    cfg: CascadeConfig,
    attack_intervals: Optional[Sequence[Tuple[float, float, str]]],
    label_ts_offset_sec: float,
) -> tuple[pd.DataFrame, pd.DataFrame, Optional[float]]:
    t_cut: Optional[float] = None
    if cfg.train_frac is not None:
        if not (0.0 < cfg.train_frac < 1.0):
            raise ValueError("train_frac must be strictly between 0 and 1, or None")
        t_cut = _time_cut(df, cfg.train_frac)

    feat_fit = feat if t_cut is None else feat[feat["t_end"] <= t_cut].copy()
    if t_cut is None:
        pkt_fit = pkt
    else:
        row_train = df["ts"].values < t_cut
        pkt_fit = pkt.loc[row_train].copy()

    if len(feat_fit) == 0 or len(pkt_fit) == 0:
        raise ValueError("Train split produced empty feat_fit or pkt_fit; adjust train_frac.")

    if cfg.fit_benign_only:
        if not attack_intervals:
            raise ValueError("fit_benign_only=True requires non-empty attack_intervals")
        off = float(label_ts_offset_sec)
        win_hit = window_attack_overlap_labels(feat_fit, attack_intervals, offset_sec=off)
        feat_fit = feat_fit.loc[win_hit == 0].copy()
        idx = pkt_fit.index.to_numpy()
        ts_sub = df.loc[idx, "ts"].values.astype(np.float64)
        row_hit = packet_attack_labels(ts_sub, attack_intervals, offset_sec=off)
        pkt_fit = pkt_fit.loc[row_hit == 0].copy()
        if len(feat_fit) == 0 or len(pkt_fit) == 0:
            raise ValueError(
                "fit_benign_only removed all fit rows (check label_ts_offset_sec vs JSONL intervals "
                "or disable fit_benign_only)."
            )
    return feat_fit, pkt_fit, t_cut


def fit_train_score_eval(
    df_train: pd.DataFrame,
    df_score: pd.DataFrame,
    cfg: CascadeConfig,
    *,
    attack_intervals: Optional[Sequence[Tuple[float, float, str]]] = None,
    label_ts_offset_sec: float = 0.0,
) -> CascadeResult:
    """
    Fit scalers + Isolation Forests on **df_train**, then score **df_score** (e.g. benign train CSV
    then mixed eval capture). ``CascadeResult`` fields refer to the **scoring** dataframe.
    """
    df_tr, t0_tr = assign_window_index(df_train, cfg.window_sec)
    feat_tr = build_window_features(df_tr, cfg.window_sec, t0_tr)
    win_cols = window_feature_columns(
        feat_tr, include_dst_context=cfg.include_dst_context, drop_src_identity=cfg.drop_src_identity
    )
    pkt_tr = build_packet_table(df_tr, include_dst=cfg.packet_include_dst)
    pkt_cols = packet_feature_columns(pkt_tr, include_dst=cfg.packet_include_dst)

    feat_fit, pkt_fit, t_cut = _feat_pkt_fit_subset(
        df_tr, feat_tr, pkt_tr, cfg, attack_intervals, label_ts_offset_sec
    )
    scaler_w, scaler_p, if_win, if_pkt = _train_isolation_forests(
        cfg, feat_fit, pkt_fit, win_cols, pkt_cols
    )

    df_ev, t0_ev = assign_window_index(df_score, cfg.window_sec)
    feat_ev = build_window_features(df_ev, cfg.window_sec, t0_ev)
    pkt_ev = build_packet_table(df_ev, include_dst=cfg.packet_include_dst)
    feat_ev, pkt_ev = _score_and_cascade(
        cfg, scaler_w, scaler_p, if_win, if_pkt, feat_ev, pkt_ev, df_ev, win_cols, pkt_cols
    )
    return CascadeResult(
        df=df_ev,
        feat=feat_ev,
        pkt=pkt_ev,
        t_cut=t_cut,
        config=cfg,
        separate_eval_corpus=True,
    )


def fit_and_score(
    df: pd.DataFrame,
    cfg: CascadeConfig,
    *,
    attack_intervals: Optional[Sequence[Tuple[float, float, str]]] = None,
    label_ts_offset_sec: float = 0.0,
) -> CascadeResult:
    df, t0 = assign_window_index(df, cfg.window_sec)
    feat = build_window_features(df, cfg.window_sec, t0)
    win_cols = window_feature_columns(
        feat, include_dst_context=cfg.include_dst_context, drop_src_identity=cfg.drop_src_identity
    )
    pkt = build_packet_table(df, include_dst=cfg.packet_include_dst)
    pkt_cols = packet_feature_columns(pkt, include_dst=cfg.packet_include_dst)

    feat_fit, pkt_fit, t_cut = _feat_pkt_fit_subset(
        df, feat, pkt, cfg, attack_intervals, label_ts_offset_sec
    )
    scaler_w, scaler_p, if_win, if_pkt = _train_isolation_forests(
        cfg, feat_fit, pkt_fit, win_cols, pkt_cols
    )
    feat, pkt = _score_and_cascade(
        cfg, scaler_w, scaler_p, if_win, if_pkt, feat, pkt, df, win_cols, pkt_cols
    )
    return CascadeResult(
        df=df, feat=feat, pkt=pkt, t_cut=t_cut, config=cfg, separate_eval_corpus=False
    )


def packet_attack_labels(
    ts: np.ndarray, intervals: Sequence[Tuple[float, float, str]], *, offset_sec: float = 0.0
) -> np.ndarray:
    te = ts.astype(np.float64) + float(offset_sec)
    inside = np.zeros(len(te), dtype=bool)
    for t0, t1, _ in intervals:
        inside |= (te >= t0) & (te <= t1)
    return inside.astype(np.int8)


def window_attack_overlap_labels(
    feat: pd.DataFrame, intervals: Sequence[Tuple[float, float, str]], *, offset_sec: float = 0.0
) -> np.ndarray:
    labels: List[int] = []
    off = float(offset_sec)
    for _, row in feat.iterrows():
        a0 = float(row["t_start"]) + off
        a1 = float(row["t_end"]) + off
        hit = any(intervals_overlap(a0, a1, t0, t1) for t0, t1, _ in intervals)
        labels.append(1 if hit else 0)
    return np.array(labels, dtype=np.int8)


def interval_epoch_bounds(intervals: Sequence[Tuple[float, float, str]]) -> tuple[Optional[float], Optional[float]]:
    if not intervals:
        return None, None
    return min(t[0] for t in intervals), max(t[1] for t in intervals)


def first_orchestrator_start_epoch(paths: Sequence[Path]) -> Optional[float]:
    """First ``orchestrator_start`` timestamp across JSONL files (epoch seconds)."""
    for path in paths:
        p = Path(path)
        if not p.exists():
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                o = json.loads(line)
                if o.get("event") != "orchestrator_start":
                    continue
                ts = _iso_to_epoch(o.get("ts_iso"))
                if ts is not None:
                    return float(ts)
    return None


def _count_packets_in_intervals(ts: np.ndarray, intervals: Sequence[Tuple[float, float, str]], off: float) -> int:
    if not intervals or len(ts) == 0:
        return 0
    te = ts.astype(np.float64) + float(off)
    t_starts = np.array([x[0] for x in intervals], dtype=np.float64)
    t_ends = np.array([x[1] for x in intervals], dtype=np.float64)
    mask = np.zeros(len(te), dtype=bool)
    for i in range(len(t_starts)):
        mask |= (te >= t_starts[i]) & (te <= t_ends[i])
    return int(mask.sum())


def suggest_eval_ts_offset_sec(
    ts: np.ndarray,
    intervals: Sequence[Tuple[float, float, str]],
    *,
    coarse_step_sec: float = 300.0,
    span_hours: float = 14.0,
    refine_step_sec: float = 15.0,
) -> tuple[float, int]:
    """
    Grid-search an additive offset ``d`` (applied as ``ts + d``) to maximize how many
    packet timestamps fall inside any JSONL episode interval. Use when CSV epoch and
    JSONL ``ts_iso`` disagree (e.g. naive local clock vs UTC).
    """
    if not intervals:
        return 0.0, 0
    ts = np.asarray(ts, dtype=np.float64)
    half = float(span_hours) * 3600.0
    best_off, best_hits = 0.0, -1
    for off in np.arange(-half, half + 1e-6, coarse_step_sec):
        h = _count_packets_in_intervals(ts, intervals, float(off))
        if h > best_hits:
            best_hits, best_off = h, float(off)
    lo = best_off - coarse_step_sec
    hi = best_off + coarse_step_sec
    for off in np.arange(lo, hi + 1e-6, refine_step_sec):
        h = _count_packets_in_intervals(ts, intervals, float(off))
        if h > best_hits:
            best_hits, best_off = h, float(off)
    return best_off, best_hits


def time_alignment_report(
    ts: np.ndarray, intervals: Sequence[Tuple[float, float, str]], *, offset_sec: float = 0.0
) -> str:
    ts = np.asarray(ts, dtype=np.float64)
    imn, imx = interval_epoch_bounds(intervals)
    lines = [
        "Time alignment (epoch seconds)",
        f"  CSV packets: n={len(ts)} min={float(ts.min()):.3f} max={float(ts.max()):.3f}",
    ]
    if imn is None:
        lines.append("  JSONL episode union: (no intervals)")
    else:
        lines.append(
            f"  JSONL episode union: n_intervals={len(intervals)} min={imn:.3f} max={imx:.3f}"
        )
        nh = _count_packets_in_intervals(ts, intervals, float(offset_sec))
        denom = max(1, len(ts))
        lines.append(
            f"  Packets inside any interval (ts + {offset_sec:g}): {nh} ({100.0 * nh / denom:.3f}%)"
        )
    return "\n".join(lines)
