#!/usr/bin/env python3
"""
Autonomous IDS dataset driver: spaces attack episodes with jitter and logs UTC
JSONL events so PCAPs can be aligned with labels offline.

Capture traffic on your mirror/tap/SPAN or host interface; this process only
emits ground-truth timestamps (it does not write pcaps).
"""
from __future__ import annotations

import argparse
import json
import os
import random
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def detect_outbound_ip(target_host: str, target_port: int) -> str:
    """Local IPv4 used to reach target (UDP connect does not send packets)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_host, target_port))
        return s.getsockname()[0]
    finally:
        s.close()


def log_event(path: Path, record: dict[str, Any], base: Optional[Dict[str, Any]] = None) -> None:
    merged: dict[str, Any] = {**(base or {}), **record}
    merged["ts_iso"] = utc_now_iso()
    line = json.dumps(merged, separators=(",", ":"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line, flush=True)


def parse_host_port(s: str) -> tuple[str, int]:
    host, _, port_s = s.partition(":")
    if not port_s:
        raise ValueError(f"Expected HOST:PORT, got {s!r}")
    return host, int(port_s)


def build_cmd(
    scripts_dir: Path,
    python: str,
    argv: List[str],
) -> List[str]:
    return [python, str(scripts_dir / argv[0])] + argv[1:]


def episode_read_bulk(host: str, port: int, unit: int) -> List[str]:
    return [
        "read_bulk.py",
        host,
        "--start",
        str(random.randint(0, 50)),
        "--total",
        str(random.randint(200, 900)),
        "--port",
        str(port),
        "--unit",
        str(unit),
        "--loops",
        str(random.randint(1, 4)),
        "--sleep-between",
        f"{random.uniform(1.5, 8.0):.2f}",
    ]


def episode_read_fc(host: str, port: int, unit: int) -> List[str]:
    return [
        "read_fc_probe.py",
        host,
        str(port),
        "--unit",
        str(unit),
        "--loops",
        str(random.randint(2, 6)),
        "--sleep-between",
        f"{random.uniform(3.0, 20.0):.2f}",
    ]


def episode_write_bulk(host: str, port: int, unit: int) -> List[str]:
    return [
        "write_bulk.py",
        host,
        "--start",
        str(random.randint(0, 80)),
        "--count",
        str(random.randint(40, 120)),
        "--value",
        str(random.choice([0, 1, 65535, 12345])),
        "--port",
        str(port),
        "--unit",
        str(unit),
        "--loops",
        "1",
    ]


def episode_write_dangerous(host: str, port: int, unit: int) -> List[str]:
    pairs = []
    for _ in range(random.randint(1, 3)):
        addr = random.randint(40, 120)
        val = random.choice([0, 9999, 65535, 32768])
        pairs.append(f"{addr}:{val}")
    return [
        "write_dangerous.py",
        host,
        *pairs,
        "--port",
        str(port),
        "--unit",
        str(unit),
        "--loops",
        str(random.randint(1, 3)),
        "--sleep-between",
        f"{random.uniform(2.0, 12.0):.2f}",
    ]


def episode_dos(host: str, port: int, unit: int) -> List[str]:
    return [
        "DOS_Attack_Sim.py",
        "--target",
        host,
        "--port",
        str(port),
        "--unit",
        str(unit),
        "--duration",
        f"{random.uniform(4.0, 14.0):.1f}",
        "--rps",
        str(random.randint(8, 45)),
    ]


def run_episode(
    *,
    scripts_dir: Path,
    python: str,
    events_path: Path,
    attack_id: str,
    argv: List[str],
    episode_timeout: Optional[float],
    log_base: Optional[Dict[str, Any]],
) -> int:
    cmd = build_cmd(scripts_dir, python, argv)
    log_event(
        events_path,
        {
            "event": "episode_start",
            "attack_id": attack_id,
            "argv": argv,
            "cmd": cmd,
        },
        log_base,
    )
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(scripts_dir),
            timeout=episode_timeout,
        )
        code = proc.returncode
    except subprocess.TimeoutExpired:
        code = -1
        log_event(
            events_path,
            {
                "event": "episode_timeout",
                "attack_id": attack_id,
                "timeout_sec": episode_timeout,
            },
            log_base,
        )
    dur = time.perf_counter() - t0
    log_event(
        events_path,
        {
            "event": "episode_end",
            "attack_id": attack_id,
            "exit_code": code,
            "duration_sec": round(dur, 4),
        },
        log_base,
    )
    return code


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Schedule Modbus attack episodes with benign gaps; log JSONL for PCAP alignment."
    )
    parser.add_argument(
        "--events-out",
        default=os.environ.get("IDS_EVENTS_OUT", "/data/ids_events.jsonl"),
        help="Append-only JSONL log path (default: /data/ids_events.jsonl)",
    )
    parser.add_argument(
        "--plc1",
        default=os.environ.get("IDS_ORCH_PLC1", "10.30.0.3:5020"),
        help="First PLC as HOST:PORT",
    )
    parser.add_argument(
        "--plc2",
        default=os.environ.get("IDS_ORCH_PLC2", "10.30.0.5:5020"),
        help="Second PLC as HOST:PORT",
    )
    parser.add_argument(
        "--min-gap",
        type=float,
        default=float(os.environ.get("IDS_MIN_GAP_SEC", "25")),
        help="Minimum seconds between episode starts (benign window lower bound)",
    )
    parser.add_argument(
        "--max-gap",
        type=float,
        default=float(os.environ.get("IDS_MAX_GAP_SEC", "180")),
        help="Maximum seconds between episode starts",
    )
    parser.add_argument(
        "--attack-probability",
        type=float,
        default=float(os.environ.get("IDS_ATTACK_PROB", "0.72")),
        help="Probability of running an attack after each gap (else extended benign-only sleep)",
    )
    parser.add_argument(
        "--benign-extra-max",
        type=float,
        default=float(os.environ.get("IDS_BENIGN_EXTRA_MAX", "240")),
        help="When no attack is chosen, extra random sleep up to this many seconds",
    )
    parser.add_argument(
        "--episode-timeout",
        type=float,
        default=float(os.environ.get("IDS_EPISODE_TIMEOUT", "600")),
        help="Hard cap on subprocess runtime (seconds)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="RNG seed for reproducible schedules",
    )
    parser.add_argument(
        "--unit",
        type=int,
        default=int(os.environ.get("IDS_MODBUS_UNIT", "0")),
        help="Modbus unit/slave id for attack subprocesses (match your PLC)",
    )
    parser.add_argument(
        "--source-ip",
        default=os.environ.get("IDS_SOURCE_IP", "").strip(),
        help="IPv4 of this attacker (set per orchestrator so PCAP source varies; auto-detected if empty)",
    )
    parser.add_argument(
        "--attacker-id",
        default=os.environ.get("IDS_ATTACKER_ID", "").strip(),
        help="Stable id for this orchestrator instance (defaults to container hostname)",
    )
    args = parser.parse_args()

    if args.min_gap > args.max_gap:
        parser.error("--min-gap must be <= --max-gap")

    scripts_dir = Path(__file__).resolve().parent
    events_path = Path(args.events_out)
    plc1_h, plc1_p = parse_host_port(args.plc1)
    plc2_h, plc2_p = parse_host_port(args.plc2)

    log_base: Dict[str, Any] = {}
    src_ip = args.source_ip
    if not src_ip:
        try:
            src_ip = detect_outbound_ip(plc1_h, plc1_p)
        except OSError:
            src_ip = ""
    if src_ip:
        log_base["source_ip"] = src_ip
    aid = args.attacker_id or os.environ.get("HOSTNAME", socket.gethostname())
    if aid:
        log_base["attacker_id"] = aid

    if args.seed is not None:
        random.seed(args.seed)

    u = args.unit
    weighted_episodes: List[tuple[float, str, Callable[[], List[str]]]] = [
        (1.0, "read_bulk_plc1", lambda: episode_read_bulk(plc1_h, plc1_p, u)),
        (1.0, "read_bulk_plc2", lambda: episode_read_bulk(plc2_h, plc2_p, u)),
        (0.9, "read_fc_plc2", lambda: episode_read_fc(plc2_h, plc2_p, u)),
        (0.8, "write_bulk_plc2", lambda: episode_write_bulk(plc2_h, plc2_p, u)),
        (0.85, "write_dangerous_plc1", lambda: episode_write_dangerous(plc1_h, plc1_p, u)),
        (0.55, "dos_plc2", lambda: episode_dos(plc2_h, plc2_p, u)),
    ]

    def pick_episode() -> tuple[str, Callable[[], List[str]]]:
        total = sum(w for w, _, _ in weighted_episodes)
        r = random.uniform(0, total)
        acc = 0.0
        for w, aid, fn in weighted_episodes:
            acc += w
            if r <= acc:
                return aid, fn
        return weighted_episodes[-1][1], weighted_episodes[-1][2]

    log_event(
        events_path,
        {
            "event": "orchestrator_start",
            "plc1": args.plc1,
            "plc2": args.plc2,
            "min_gap": args.min_gap,
            "max_gap": args.max_gap,
            "attack_probability": args.attack_probability,
            "seed": args.seed,
        },
        log_base,
    )

    try:
        while True:
            gap = random.uniform(args.min_gap, args.max_gap)
            log_event(
                events_path,
                {"event": "gap_sleep", "duration_sec": round(gap, 3), "phase": "benign"},
                log_base,
            )
            time.sleep(gap)

            if random.random() > args.attack_probability:
                extra = random.uniform(0, args.benign_extra_max)
                log_event(
                    events_path,
                    {
                        "event": "benign_only_extension",
                        "duration_sec": round(extra, 3),
                        "phase": "benign",
                    },
                    log_base,
                )
                time.sleep(extra)
                continue

            attack_id, builder = pick_episode()
            argv = builder()
            run_episode(
                scripts_dir=scripts_dir,
                python=sys.executable,
                events_path=events_path,
                attack_id=attack_id,
                argv=argv,
                episode_timeout=args.episode_timeout,
                log_base=log_base,
            )
    except KeyboardInterrupt:
        log_event(
            events_path,
            {"event": "orchestrator_stop", "reason": "keyboard_interrupt"},
            log_base,
        )


if __name__ == "__main__":
    main()
