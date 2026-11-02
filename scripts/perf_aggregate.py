#!/usr/bin/env python3
"""汇总 perf.sh 的原始数据为 summary.md + summary.json。

输入(results 目录):
  rounds.jsonl  每轮一行 JSON(ksbench bench 输出)
  rss.csv       每秒一行 epoch,rss_kb(网关进程)
  markers.log   场景起止时间戳
  env.txt       环境记录
输出:
  summary.md    人读汇总:轮间中位数表 + d/g 成对开销表 + RSS/soak 概览
  summary.json  同数据的机器可读版

只做聚合不做解读;结论写进 docs/perf-report-*.md。
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from pathlib import Path

METRICS = [
    "rps",
    "ttfb_us.p50",
    "ttfb_us.p90",
    "ttfb_us.p99",
    "total_us.p50",
    "total_us.p90",
    "total_us.p99",
    "sse.chunk_gap_us.p50",
    "sse.chunk_gap_us.p99",
    "ok",
    "http_errors",
    "transport_errors",
]


def dig(row: dict, path: str):
    """按 a.b 取嵌套字段;SSE 字段缺失时返回 None。"""
    cur = row
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def fmt_us(v) -> str:
    return "—" if v is None else f"{v / 1000:.2f}ms" if v >= 1000 else f"{v:.0f}µs"


def fmt_num(v) -> str:
    return "—" if v is None else f"{v:,.0f}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", required=True, type=Path)
    args = ap.parse_args()
    res = args.results

    rounds = defaultdict(list)
    for line in (res / "rounds.jsonl").read_text().splitlines():
        line = line.strip()
        if line.startswith("{"):
            row = json.loads(line)
            rounds[row["label"]].append(row)

    # 每标签、每指标取轮间中位数 ---------------------------------------------
    median: dict[str, dict] = {}
    cv: dict[str, float] = {}
    for label, rows in sorted(rounds.items()):
        m = {}
        for path in METRICS:
            vals = [dig(r, path) for r in rows]
            vals = [v for v in vals if v is not None]
            m[path] = statistics.median(vals) if vals else None
        median[label] = m
        rps_vals = [r["rps"] for r in rows]
        if len(rps_vals) > 1 and statistics.median(rps_vals) > 0:
            spread = (max(rps_vals) - min(rps_vals)) / statistics.median(rps_vals)
            cv[label] = spread

    # RSS ---------------------------------------------------------------------
    rss_note = ""
    rss = []
    rss_file = res / "rss.csv"
    if rss_file.exists():
        for line in rss_file.read_text().splitlines():
            parts = line.split(",")
            if len(parts) == 2 and parts[1].isdigit():
                rss.append(int(parts[1]))
    if rss:
        rss_note = (
            f"min {min(rss) / 1024:.0f}MB · first {rss[0] / 1024:.0f}MB · "
            f"last {rss[-1] / 1024:.0f}MB · peak {max(rss) / 1024:.0f}MB "
            f"({len(rss)} samples)"
        )

    # 渲染 ---------------------------------------------------------------------
    out = []
    out.append("# perf summary\n")
    env = (res / "env.txt").read_text().strip() if (res / "env.txt").exists() else ""
    if env:
        out.append("```")
        out.append(env)
        out.append("```\n")

    out.append("## per-scenario medians (rounds→median)\n")
    out.append(
        "| label | rounds | rps | ttfb p50 | ttfb p99 | total p50 | total p99 "
        "| gap p50 | gap p99 | ok | err | rps spread |"
    )
    out.append("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for label, m in median.items():
        errs = (m["http_errors"] or 0) + (m["transport_errors"] or 0)
        spread = cv.get(label)
        out.append(
            f"| {label} | {len(rounds[label])} "
            f"| {fmt_num(m['rps'])} "
            f"| {fmt_us(m['ttfb_us.p50'])} | {fmt_us(m['ttfb_us.p99'])} "
            f"| {fmt_us(m['total_us.p50'])} | {fmt_us(m['total_us.p99'])} "
            f"| {fmt_us(m['sse.chunk_gap_us.p50'])} | {fmt_us(m['sse.chunk_gap_us.p99'])} "
            f"| {fmt_num(m['ok'])} | {fmt_num(errs)} "
            f"| {'—' if spread is None else f'{spread * 100:.0f}%'} |"
        )
    out.append("")

    # d/X ↔ g/X 成对开销 -------------------------------------------------------
    pairs = sorted(
        {
            label[2:]
            for label in median
            if label.startswith("d/") and f"g/{label[2:]}" in median
        }
    )
    if pairs:
        out.append("## gateway overhead (g/X − d/X, latency in µs)\n")
        out.append(
            "| scenario | Δttfb p50 | Δttfb p99 | Δtotal p50 | Δtotal p99 "
            "| rps g/d |"
        )
        out.append("|---|---|---|---|---|---|")
        for p in pairs:
            d, g = median[f"d/{p}"], median[f"g/{p}"]

            def delta(path):
                if d[path] is None or g[path] is None:
                    return None
                return g[path] - d[path]

            ratio = (
                "—"
                if not d["rps"]
                else f"{g['rps'] / d['rps']:.2f}x"
                if g["rps"] is not None
                else "—"
            )
            out.append(
                f"| {p} "
                f"| {fmt_us(delta('ttfb_us.p50'))} | {fmt_us(delta('ttfb_us.p99'))} "
                f"| {fmt_us(delta('total_us.p50'))} | {fmt_us(delta('total_us.p99'))} "
                f"| {ratio} |"
            )
        out.append("")

    if rss_note:
        out.append("## gateway RSS\n")
        out.append(rss_note + "\n")

    # S7 reload 单独一行说明(数据已在 per-scenario 表里)
    if "g/reload_under_load" in median:
        m = median["g/reload_under_load"]
        base = median.get("g/small_c32")
        out.append("## hot reload under load\n")
        out.append(
            f"- errors: {fmt_num((m['http_errors'] or 0) + (m['transport_errors'] or 0))}"
        )
        if base:
            out.append(
                f"- total p99 {fmt_us(m['total_us.p99'])} "
                f"(baseline g/small_c32 p99 {fmt_us(base['total_us.p99'])})"
            )
        out.append("")

    md = "\n".join(out)
    (res / "summary.md").write_text(md)
    (res / "summary.json").write_text(
        json.dumps({"median": median, "cv": cv, "rss": rss}, indent=1)
    )
    print(md)


if __name__ == "__main__":
    main()
