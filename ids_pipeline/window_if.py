"""Modbus IDS: windowed Isolation Forest on aggregated per-window features (unsupervised)."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional, Sequence, Tuple, Union

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

Contamination = Union[float, str]

# (t_start_epoch, t_end_epoch, attack_id, orchestrator source_ip from JSONL)
AttackInterval = Tuple[float, float, str, str]


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
    if "Src IP" in df.columns:
        df["Src IP"] = df["Src IP"].astype(str)
    else:
        df["Src IP"] = ""
    df["ts"] = (df["Time"] - pd.Timestamp("1970-01-01")) / pd.Timedelta("1s")
    return df


def assign_window_index(df: pd.DataFrame, window_sec: float) -> tuple[pd.DataFrame, float]:
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
        n_unique_src = int(g["Src IP"].nunique()) if "Src IP" in g.columns else 0
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
            "n_unique_src": n_unique_src,
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
    feat: pd.DataFrame,
    *,
    include_src_context: bool,
    include_dst_context: bool,
    drop_src_identity: bool,
) -> List[str]:
    cols = [c for c in feat.columns if c not in ("w", "t_start", "t_end")]
    if drop_src_identity:
        cols = [c for c in cols if c not in ("n_unique_src", "n_unique_dst")]
    else:
        if not include_src_context:
            cols = [c for c in cols if c != "n_unique_src"]
        if not include_dst_context:
            cols = [c for c in cols if c != "n_unique_dst"]
    return cols


def _iso_to_epoch(s: Any) -> Optional[float]:
    if not s:
        return None
    return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()


def load_attack_intervals_epoch(path: Path) -> List[AttackInterval]:
    pending: defaultdict[str, deque] = defaultdict(deque)
    out: List[AttackInterval] = []
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
                sip = str(o.get("source_ip") or "")
                pending[aid].append((ts, sip))
            elif ev == "episode_end" and aid:
                if not pending[aid]:
                    continue
                t0, sip = pending[aid].popleft()
                t1 = ts
                if t1 < t0:
                    t0, t1 = t1, t0
                out.append((t0, t1, aid, sip))
    return out


def load_attack_intervals(paths: Sequence[Path]) -> List[AttackInterval]:
    out: List[AttackInterval] = []
    for p in paths:
        out.extend(load_attack_intervals_epoch(Path(p)))
    return out


def resolve_label_ts_offset(
    ts: np.ndarray,
    jsonl_paths: Sequence[Path],
    manual_offset_sec: Optional[float],
) -> tuple[float, List[AttackInterval]]:
    intervals = load_attack_intervals(jsonl_paths)
    if manual_offset_sec is not None:
        return float(manual_offset_sec), intervals
    off, _hits = suggest_eval_ts_offset_sec(ts, intervals)
    return float(off), intervals


def intervals_overlap(a0: float, a1: float, b0: float, b1: float) -> bool:
    return (a1 >= b0) and (b1 >= a0)


@dataclass
class WindowIFConfig:
    window_sec: float = 10.0
    # n_unique_src / n_unique_dst: toggles and privacy (see window_feature_columns).
    include_src_context: bool = True
    include_dst_context: bool = True
    drop_src_identity: bool = False
    win_contamination: Contamination = "auto"
    n_estimators: int = 300
    train_frac: Optional[float] = None
    fit_benign_only: bool = False
    random_state: int = 42
    """If set in (0,1), ``if_pred`` uses this quantile of ``decision_function`` on **fit** rows."""
    benign_alert_quantile: Optional[float] = None


@dataclass
class WindowIFResult:
    df: pd.DataFrame
    feat: pd.DataFrame
    t_cut: Optional[float]
    config: WindowIFConfig
    separate_eval_corpus: bool
    benign_thresh_win: Optional[float] = None
    # IF decision_function on each **fit** window (benign training rows), for threshold sweeps.
    train_if_scores: Optional[np.ndarray] = None


def _contam_arg(c: Contamination) -> Any:
    return c if c == "auto" else float(c)


def _time_cut(df: pd.DataFrame, train_frac: float) -> float:
    t_min = float(df["ts"].min())
    t_max = float(df["ts"].max())
    return t_min + float(train_frac) * (t_max - t_min)


def _feat_fit_subset_from_df(
    df: pd.DataFrame,
    feat: pd.DataFrame,
    cfg: WindowIFConfig,
    attack_intervals: Optional[Sequence[AttackInterval]],
    label_ts_offset_sec: float,
) -> tuple[pd.DataFrame, Optional[float]]:
    t_cut: Optional[float] = None
    if cfg.train_frac is not None:
        if not (0.0 < cfg.train_frac < 1.0):
            raise ValueError("train_frac must be strictly between 0 and 1, or None")
        t_cut = _time_cut(df, cfg.train_frac)
        feat_fit = feat[feat["t_end"] <= t_cut].copy()
    else:
        feat_fit = feat

    if len(feat_fit) == 0:
        raise ValueError("Train split produced empty feat_fit; adjust train_frac.")

    if cfg.fit_benign_only:
        if not attack_intervals:
            raise ValueError("fit_benign_only=True requires non-empty attack_intervals")
        off = float(label_ts_offset_sec)
        win_hit = window_attack_overlap_labels(feat_fit, attack_intervals, offset_sec=off)
        feat_fit = feat_fit.loc[win_hit == 0].copy()
        if len(feat_fit) == 0:
            raise ValueError(
                "fit_benign_only removed all windows (check label_ts_offset_sec vs JSONL intervals)."
            )
    return feat_fit, t_cut


def _train_window_if(
    cfg: WindowIFConfig,
    feat_fit: pd.DataFrame,
    win_cols: List[str],
) -> tuple[StandardScaler, IsolationForest, Optional[float], np.ndarray]:
    Xw = feat_fit[win_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    scaler_w = StandardScaler()
    Xwz = scaler_w.fit_transform(Xw)
    if_win = IsolationForest(
        n_estimators=cfg.n_estimators,
        contamination=_contam_arg(cfg.win_contamination),
        random_state=cfg.random_state,
        n_jobs=-1,
    )
    if_win.fit(Xwz)
    train_if_scores = np.asarray(if_win.decision_function(Xwz), dtype=np.float64)
    benign_thresh: Optional[float] = None
    if cfg.benign_alert_quantile is not None:
        q = float(cfg.benign_alert_quantile)
        if not (0.0 < q < 1.0):
            raise ValueError("benign_alert_quantile must be strictly between 0 and 1")
        benign_thresh = float(np.quantile(train_if_scores, q))
    return scaler_w, if_win, benign_thresh, train_if_scores


def _score_windows(
    feat: pd.DataFrame,
    scaler_w: StandardScaler,
    if_win: IsolationForest,
    win_cols: List[str],
    *,
    benign_thresh_win: Optional[float] = None,
) -> pd.DataFrame:
    feat = feat.copy()
    Xw_all = feat[win_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    Xwz_all = scaler_w.transform(Xw_all)
    feat["if_score"] = if_win.decision_function(Xwz_all)
    if benign_thresh_win is not None:
        tw = float(benign_thresh_win)
        feat["if_pred"] = np.where(feat["if_score"].values <= tw, -1, 1).astype(np.int8)
    else:
        feat["if_pred"] = if_win.predict(Xwz_all)
    return feat


def fit_train_score_eval(
    df_train: pd.DataFrame,
    df_score: pd.DataFrame,
    cfg: WindowIFConfig,
    *,
    attack_intervals: Optional[Sequence[AttackInterval]] = None,
    label_ts_offset_sec: float = 0.0,
) -> WindowIFResult:
    df_tr, t0_tr = assign_window_index(df_train, cfg.window_sec)
    feat_tr = build_window_features(df_tr, cfg.window_sec, t0_tr)
    win_cols = window_feature_columns(
        feat_tr,
        include_src_context=cfg.include_src_context,
        include_dst_context=cfg.include_dst_context,
        drop_src_identity=cfg.drop_src_identity,
    )
    feat_fit, t_cut = _feat_fit_subset_from_df(
        df_tr, feat_tr, cfg, attack_intervals, label_ts_offset_sec
    )
    scaler_w, if_win, benign_tw, train_if_scores = _train_window_if(cfg, feat_fit, win_cols)

    df_ev, t0_ev = assign_window_index(df_score, cfg.window_sec)
    feat_ev = build_window_features(df_ev, cfg.window_sec, t0_ev)
    feat_ev = _score_windows(feat_ev, scaler_w, if_win, win_cols, benign_thresh_win=benign_tw)
    return WindowIFResult(
        df=df_ev,
        feat=feat_ev,
        t_cut=t_cut,
        config=cfg,
        separate_eval_corpus=True,
        benign_thresh_win=benign_tw,
        train_if_scores=train_if_scores,
    )


def fit_and_score(
    df: pd.DataFrame,
    cfg: WindowIFConfig,
    *,
    attack_intervals: Optional[Sequence[AttackInterval]] = None,
    label_ts_offset_sec: float = 0.0,
) -> WindowIFResult:
    df, t0 = assign_window_index(df, cfg.window_sec)
    feat = build_window_features(df, cfg.window_sec, t0)
    win_cols = window_feature_columns(
        feat,
        include_src_context=cfg.include_src_context,
        include_dst_context=cfg.include_dst_context,
        drop_src_identity=cfg.drop_src_identity,
    )
    feat_fit, t_cut = _feat_fit_subset_from_df(
        df,
        feat,
        cfg,
        attack_intervals,
        label_ts_offset_sec,
    )
    scaler_w, if_win, benign_tw, train_if_scores = _train_window_if(cfg, feat_fit, win_cols)
    feat = _score_windows(feat, scaler_w, if_win, win_cols, benign_thresh_win=benign_tw)
    return WindowIFResult(
        df=df,
        feat=feat,
        t_cut=t_cut,
        config=cfg,
        separate_eval_corpus=False,
        benign_thresh_win=benign_tw,
        train_if_scores=train_if_scores,
    )


def apply_benign_quantile_threshold(
    feat: pd.DataFrame,
    train_if_scores: np.ndarray,
    q: float,
) -> tuple[pd.DataFrame, float]:
    """
    Recompute ``if_pred`` on eval ``feat`` without refitting: anomaly iff
    ``if_score <= quantile(train_if_scores, q)`` (train distribution only).
    """
    if not (0.0 < q < 1.0):
        raise ValueError("q must be strictly between 0 and 1")
    ts = np.asarray(train_if_scores, dtype=np.float64).ravel()
    if ts.size == 0:
        raise ValueError("train_if_scores is empty")
    t = float(np.quantile(ts, q))
    out = feat.copy()
    out["if_pred"] = np.where(out["if_score"].values <= t, -1, 1).astype(np.int8)
    return out, t


def window_overlap_recall(y_overlap: np.ndarray, if_pred: np.ndarray) -> float:
    """Recall for positive = JSONL-overlap window; detection = ``if_pred == -1``."""
    y = np.asarray(y_overlap, dtype=np.int8).ravel()
    p = np.asarray(if_pred, dtype=np.int8).ravel()
    pos = y == 1
    if not np.any(pos):
        return 0.0
    return float(((p == -1) & pos).sum() / float(pos.sum()))


def min_quantile_for_window_recall(
    feat: pd.DataFrame,
    train_if_scores: np.ndarray,
    y_overlap: np.ndarray,
    *,
    target_recall: float = 0.6,
    q_min: float = 0.02,
    q_max: float = 0.92,
    n_steps: int = 91,
) -> tuple[float, float, np.ndarray]:
    """
    Scan ``q`` ascending in ``[q_min, q_max]``; return the **first** ``q`` whose overlap recall
    meets ``target_recall``. If never met, return the ``q`` with **best** recall on the grid
    (typically near ``q_max``).
    """
    q_grid = np.linspace(q_min, q_max, n_steps)
    y = np.asarray(y_overlap, dtype=np.int8).ravel()
    scores = feat["if_score"].values.astype(np.float64)
    ts_fit = np.asarray(train_if_scores, dtype=np.float64).ravel()
    best_q, best_rec, best_pred = q_max, -1.0, np.ones(len(scores), dtype=np.int8)
    for q in q_grid:
        t = float(np.quantile(ts_fit, float(q)))
        pred = np.where(scores <= t, -1, 1).astype(np.int8)
        rec = window_overlap_recall(y, pred)
        if rec > best_rec:
            best_q, best_rec, best_pred = float(q), rec, pred.copy()
        if rec >= float(target_recall):
            return float(q), rec, pred
    return best_q, best_rec, best_pred


def window_overlap_precision(y_overlap: np.ndarray, if_pred: np.ndarray) -> float:
    """Precision for positive class = flagged anomalous window among overlap-positive protocol."""
    y = np.asarray(y_overlap, dtype=np.int8).ravel()
    p = np.asarray(if_pred, dtype=np.int8).ravel()
    pred_pos = p == -1
    tp = int((pred_pos & (y == 1)).sum())
    fp = int((pred_pos & (y == 0)).sum())
    if tp + fp == 0:
        return 0.0
    return float(tp / (tp + fp))


def flagged_window_fraction(if_pred: np.ndarray) -> float:
    p = np.asarray(if_pred, dtype=np.int8).ravel()
    return float((p == -1).sum() / max(1, len(p)))


def smallest_quantile_recall_under_flag_cap(
    feat: pd.DataFrame,
    train_if_scores: np.ndarray,
    y_overlap: np.ndarray,
    *,
    target_recall: float = 0.6,
    max_flagged_fraction: float = 0.35,
    q_min: float = 0.02,
    q_max: float = 0.92,
    n_steps: int = 91,
) -> tuple[Optional[float], float, float, float, float, np.ndarray]:
    """
    **Smallest** ``q`` (ascending scan) with overlap recall ``>= target_recall`` and
    ``flagged_window_fraction <= max_flagged_fraction`` (avoids “flag everything” when ``q`` is
    loose).

    Returns ``(q_met, q_applied, recall, precision, flagged_fraction, pred)``. On joint
    feasibility, ``q_met == q_applied``. If no ``q`` satisfies **both** constraints, ``q_met`` is
    ``None`` and ``q_applied`` is from :func:`max_recall_quantile_under_flag_cap` (best recall under
    the flag cap only).
    """
    q_grid = np.linspace(q_min, q_max, n_steps)
    y = np.asarray(y_overlap, dtype=np.int8).ravel()
    scores = feat["if_score"].values.astype(np.float64)
    ts_fit = np.asarray(train_if_scores, dtype=np.float64).ravel()

    for q in q_grid:
        t = float(np.quantile(ts_fit, float(q)))
        pred = np.where(scores <= t, -1, 1).astype(np.int8)
        rec = window_overlap_recall(y, pred)
        prec = window_overlap_precision(y, pred)
        ff = flagged_window_fraction(pred)
        if rec >= float(target_recall) and ff <= float(max_flagged_fraction):
            fq = float(q)
            return (fq, fq, rec, prec, ff, pred)

    q_fb, rec, prec, ff, pred = max_recall_quantile_under_flag_cap(
        feat, train_if_scores, y_overlap,
        max_flagged_fraction=max_flagged_fraction,
        q_min=q_min, q_max=q_max, n_steps=n_steps,
    )
    return (None, q_fb, rec, prec, ff, pred)


def max_recall_quantile_under_flag_cap(
    feat: pd.DataFrame,
    train_if_scores: np.ndarray,
    y_overlap: np.ndarray,
    *,
    max_flagged_fraction: float = 0.30,
    q_min: float = 0.02,
    q_max: float = 0.92,
    n_steps: int = 91,
) -> tuple[float, float, float, float, np.ndarray]:
    """
    ``q`` that **maximizes** overlap recall subject to ``flagged_window_fraction <= max_flagged_fraction``.
    Tie-break: **smaller** ``q`` (tighter threshold, fewer spurious flags).
    """
    q_grid = np.linspace(q_min, q_max, n_steps)
    y = np.asarray(y_overlap, dtype=np.int8).ravel()
    scores = feat["if_score"].values.astype(np.float64)
    ts_fit = np.asarray(train_if_scores, dtype=np.float64).ravel()
    n = len(scores)
    max_flags = int(np.ceil(max_flagged_fraction * n))

    best: Optional[tuple[float, float, float, float, np.ndarray]] = None
    for q in q_grid:
        t = float(np.quantile(ts_fit, float(q)))
        pred = np.where(scores <= t, -1, 1).astype(np.int8)
        n_flag = int((pred == -1).sum())
        if n_flag > max_flags:
            continue
        rec = window_overlap_recall(y, pred)
        prec = window_overlap_precision(y, pred)
        ff = flagged_window_fraction(pred)
        if best is None:
            best = (float(q), rec, prec, ff, pred.copy())
        elif rec > best[1] + 1e-12:
            best = (float(q), rec, prec, ff, pred.copy())
        elif abs(rec - best[1]) <= 1e-12 and float(q) < best[0]:
            best = (float(q), rec, prec, ff, pred.copy())

    if best is not None:
        return best

    t = float(np.quantile(ts_fit, float(q_min)))
    pred = np.where(scores <= t, -1, 1).astype(np.int8)
    return (
        float(q_min),
        window_overlap_recall(y, pred),
        window_overlap_precision(y, pred),
        flagged_window_fraction(pred),
        pred,
    )


def packet_attack_labels(
    ts: np.ndarray,
    intervals: Sequence[AttackInterval],
    *,
    offset_sec: float = 0.0,
    pkt_src_ip: Optional[np.ndarray] = None,
    pkt_dst_ip: Optional[np.ndarray] = None,
) -> np.ndarray:
    """Packet-level labels (optional, e.g. for cross-checks); primary IDS output is window ``feat``."""
    te = ts.astype(np.float64) + float(offset_sec)
    inside = np.zeros(len(te), dtype=bool)
    src = None if pkt_src_ip is None else np.asarray(pkt_src_ip).astype(str)
    dst = None if pkt_dst_ip is None else np.asarray(pkt_dst_ip).astype(str)
    for row in intervals:
        t0, t1 = float(row[0]), float(row[1])
        sip = str(row[3]).strip() if len(row) > 3 else ""
        time_ok = (te >= t0) & (te <= t1)
        if sip and (src is not None or dst is not None):
            host_ok = np.zeros(len(te), dtype=bool)
            if src is not None:
                host_ok |= src == sip
            if dst is not None:
                host_ok |= dst == sip
            inside |= time_ok & host_ok
        else:
            inside |= time_ok
    return inside.astype(np.int8)


def window_attack_overlap_labels(
    feat: pd.DataFrame, intervals: Sequence[AttackInterval], *, offset_sec: float = 0.0
) -> np.ndarray:
    labels: List[int] = []
    off = float(offset_sec)
    for _, row in feat.iterrows():
        a0 = float(row["t_start"]) + off
        a1 = float(row["t_end"]) + off
        hit = any(intervals_overlap(a0, a1, float(iv[0]), float(iv[1])) for iv in intervals)
        labels.append(1 if hit else 0)
    return np.array(labels, dtype=np.int8)


def interval_epoch_bounds(intervals: Sequence[AttackInterval]) -> tuple[Optional[float], Optional[float]]:
    if not intervals:
        return None, None
    return min(t[0] for t in intervals), max(t[1] for t in intervals)


def first_orchestrator_start_epoch(paths: Sequence[Path]) -> Optional[float]:
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


def _count_packets_in_intervals(ts: np.ndarray, intervals: Sequence[AttackInterval], off: float) -> int:
    if not intervals or len(ts) == 0:
        return 0
    te = ts.astype(np.float64) + float(off)
    t_starts = np.array([float(x[0]) for x in intervals], dtype=np.float64)
    t_ends = np.array([float(x[1]) for x in intervals], dtype=np.float64)
    mask = np.zeros(len(te), dtype=bool)
    for i in range(len(t_starts)):
        mask |= (te >= t_starts[i]) & (te <= t_ends[i])
    return int(mask.sum())


def suggest_eval_ts_offset_sec(
    ts: np.ndarray,
    intervals: Sequence[AttackInterval],
    *,
    coarse_step_sec: float = 300.0,
    span_hours: float = 14.0,
    refine_step_sec: float = 15.0,
) -> tuple[float, int]:
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
    ts: np.ndarray, intervals: Sequence[AttackInterval], *, offset_sec: float = 0.0
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
