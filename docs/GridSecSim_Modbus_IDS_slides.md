# GridSecSim V2 — Unsupervised Modbus IDS (slide deck outline)

*Copy sections into slides as needed. No fixed template.*

---

## Slide 1 — Title

**Unsupervised anomaly detection for Modbus traffic in a simulated electric utility**

GridSecSim V2 · Window Isolation Forest · JSONL-grounded evaluation

---

## Slide 2 — Problem motivation

- **Operational need:** Detect unusual Modbus/TCP behavior in utility-style networks without a large labeled attack corpus.
- **Constraint:** In practice you often have **captures** (CSV/PCAP-derived features) and **orchestrator logs** (JSONL episode boundaries), not per-packet “malware” labels.
- **Goal tension:** Unsupervised methods optimize for **statistical rarity**, not semantic “attack”; labels from **time windows** (JSONL episodes) only partially align with what an outlier detector sees.
- **Simulated environment:** Benign-only and mixed captures (`train_data/benign.csv`, `Full Data 4-20/fulldata2.csv`) plus `ids_events_orch*.jsonl` for episode timing and orchestrator metadata.

---

## Slide 3 — Threat / data context

- **Modbus/TCP** request/response pairs: function codes, unit IDs, transaction IDs, timing, optional `Data` string length.
- **Attack episodes** driven by an orchestrator: spaced episodes, multiple attack types (reads, writes, DoS-style scripts, etc.) logged as `episode_start` / `episode_end` with `attack_id`, `source_ip`, UTC `ts_iso`.
- **Evaluation proxy:** Packets (or windows) overlapping JSONL intervals after **clock alignment** (`EVAL_TS_OFFSET_SEC`) between CSV timestamps and JSONL UTC.

---

## Slide 4 — Proposed approach (high level)

1. **Preprocess CSV:** Parse times → robust epoch **seconds** (handles `datetime64[us]` vs `[ns]`); normalize columns.
2. **Windowing:** Fixed-duration windows (default **10 s**); aggregate **window features** (counts, entropies, IAT stats, per-FC counts, etc.).
3. **Isolation Forest on windows:** `StandardScaler` + single IF on benign training data; **`if_pred = -1`** on scored windows = anomaly.
4. **Training policy:** Fit on **benign-only** capture when available (`fit_train_score_eval`); score on mixed eval capture. Optional **`benign_alert_quantile`** on fit-benign `decision_function` instead of sklearn `predict`.
5. **Alerts:** **Anomalous time buckets** (`t_start`–`t_end`); analysts inspect PCAP / packet rows **inside** those intervals manually (no separate automated per-packet model in the main path).

---

## Slide 5 — Feature & model details

**Window features (only):** message counts, req/resp ratio, Shannon entropy on Func/Trans_ID, IAT mean/std/p95, per-function-code counts, optional `n_unique_dst`.

**Why IF:** Scales to moderate dimensionality; no labels at train time; **contamination** / quantile defines how aggressive the outlier cut is.

---

## Slide 6 — Experimental design

| Axis | Setup |
|------|--------|
| **Train** | `train_data/benign.csv` (benign-only Modbus capture) |
| **Test / eval** | `Full Data 4-20/fulldata2.csv` (mixed traffic) |
| **Labels** | JSONL `ids_events_orch{1,2,3}.jsonl` → merged episode intervals; optional **`source_ip`** on intervals for stricter packet positives |
| **Alignment** | `resolve_label_ts_offset` / grid search so CSV `ts + offset` overlaps JSONL episodes |
| **Metrics** | Window-level: `window_attack_overlap_labels` vs `feat["if_pred"]`; confusion `[[TP,FP],[FN,TN]]` |

---

## Slide 7 — Implementation artifacts

- **Code:** `ids_pipeline/window_if.py` — CSV load, windowing, features, window IF fit/score, JSONL interval helpers.
- **Notebook:** `notebooks/modbus_ids.ipynb` — paths, `WindowIFConfig`, window anomaly table, plot, evaluation vs JSONL **windows**.

---

## Slide 8 — Results (qualitative / typical patterns)

- **Clock bug fix:** CSV times inferred as `datetime64[us]` required correct epoch conversion; wrong `/1e9` collapsed time span → **one window**; fix restored **hundreds** of 10 s windows on full capture.
- **Strict orchestrator Src-only labels:** Very small positive set; with strict quantile IF, **TP** could go to **zero** (alerts landed on PLC-side traffic during episodes).
- **Loosening window thresholds** (`benign_alert_quantile` ↑): more windows flagged → better recall vs episode overlap, lower window-level precision.

---

## Slide 9 — Findings

1. **Unsupervised IF scores are weakly aligned with “attack episode” semantics** — many in-episode packets look statistically normal; many outliers are benign tails (bursts, rare FC patterns).
2. **Benign quantile calibration** decouples alert rate from sklearn’s fixed contamination story.
3. **JSONL episode boundaries** align evaluation clocks; window overlap is a **coarse** proxy for “attack period.”
4. **Recall–precision** trades off against **`benign_alert_quantile`** and contamination.

---

## Slide 10 — Challenges encountered

- **Label vs model objective:** Episode time ≠ statistical anomaly; precision/recall vs JSONL are **diagnostic**, not proof of “attack detection” in the cyber sense.
- **Train vs eval distribution:** Benign capture from a different session/day than eval shifts the normal cloud.
- **Multi-orchestrator JSONL:** Overlapping clocks and multiple `source_ip` values complicate per-interval Src matching.
- **Engineering:** Notebook/kernel reload `ids_pipeline` after edits to `window_if.py`.

---

## Slide 11 — Future work

- **Features without new raw sensors:** Parse `Data` for register ranges / write patterns; direction-aware aggregates; per-PLC baselines.
- **Calibration on eval-adjacent benign:** Quantiles from a contiguous benign slice of eval (if trustworthy) to reduce domain shift.
- **Semi-supervised / weak labels:** Use JSONL only for **training exclusion** (`fit_benign_only`) or contrastive pairs, not only evaluation.
- **Persistence / hysteresis:** Alert after *k*-of-*n* seconds or runs for stability without collapsing recall.
- **Alternative models:** One-class SVM, deep autoencoders on sequences, or **supervised** heads if any labels become available.
- **Deployment story:** High-recall window flags + **human review** of traffic inside `t_start`–`t_end`.

---

## Slide 12 — Main takeaways

- **Window-only unsupervised Modbus IDS:** single IF on aggregated windows + **JSONL-aligned window evaluation**.
- **Key lesson:** Episode time ≠ statistical anomaly; tune **`benign_alert_quantile`** / contamination for the desired alert rate on benign fit.
- **Robustness:** Time parsing and label offset are **first-class** engineering requirements; small bugs dominate “model quality” metrics.
- **Honest scope:** The system is best framed as **anomaly triage** with **orchestrator-informed** evaluation, not a proven attack detector without richer semantics or labels.

---

## Slide 13 — Q&A backup (optional)

- **Why not only JSONL for alerts?** You could OR rule-based signals, but that mixes **supervised-by-log** behavior with unsupervised learning; keep roles explicit (eval vs production rule).
- **Why Isolation Forest?** Simple, fast, no labels, well-understood contamination semantics; good baseline before heavier models.

---

*End of outline.*
