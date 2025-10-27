#!/usr/bin/env python3
import sys
import re
import argparse
import csv
import math

# This file could use the output of Criterion instead of texts...

UNIT_SCALE = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
}

def parse_duration(token: str) -> float:
    token = token.strip()
    m = re.match(r"([0-9]*\.?[0-9]+)\s*([a-zA-Zµ]+)", token)
    if not m:
        raise ValueError(f"Could not parse duration token: {token}")
    val = float(m.group(1))
    unit = m.group(2).replace("μ", "µ")
    if unit not in UNIT_SCALE:
        raise ValueError(f"Unknown time unit: {unit} in token: {token}")
    return val * UNIT_SCALE[unit]

def extract_median_from_brackets(bracket_str: str) -> float:
    # bracket_str like: '40.135 µs 40.230 µs 40.339 µs'
    parts = [p for p in bracket_str.strip().split()]
    vals = []
    i = 0
    while i < len(parts):
        num = parts[i]
        if i + 1 < len(parts):
            unit = parts[i+1]
            token = f"{num} {unit}"
            try:
                secs = parse_duration(token)
                vals.append(secs)
                i += 2
                continue
            except Exception:
                try:
                    secs = parse_duration(num)
                    vals.append(secs)
                    i += 1
                    continue
                except Exception:
                    pass
        try:
            secs = parse_duration(num)
            vals.append(secs)
        except Exception:
            pass
        i += 1
    if len(vals) < 2:
        raise ValueError(f"Could not extract three values from: {bracket_str}")
    return sorted(vals)[len(vals)//2]  # median

def parse_bench(text: str) -> dict:
    res = {}
    lines = text.splitlines()
    prev_nonempty = ""
    for line in lines:
        # Case 1: name and time on same line
        m = re.match(r"^([^\s].*?)\s+time:\s+\[(.*?)\]", line)
        if m:
            name = m.group(1).strip()
            bracket = m.group(2)
            try:
                med = extract_median_from_brackets(bracket)
                res[name] = med
            except Exception:
                pass
            prev_nonempty = name
            continue
        # Case 2: time on following line; name on previous non-empty line
        if "time:" in line:
            m2 = re.search(r"time:\s+\[(.*?)\]", line)
            if m2 and prev_nonempty:
                name = prev_nonempty.strip()
                bracket = m2.group(1)
                try:
                    med = extract_median_from_brackets(bracket)
                    res[name] = med
                except Exception:
                    pass
                continue
        stripped = line.strip()
        if stripped:
            prev_nonempty = stripped
    return res

def human_time(seconds: float) -> str:
    if seconds < 1e-6:
        return f"{seconds*1e9:.3f} ns"
    if seconds < 1e-3:
        return f"{seconds*1e6:.3f} µs"
    if seconds < 1:
        return f"{seconds*1e3:.3f} ms"
    return f"{seconds:.3f} s"

def compare(small_map: dict, big_map: dict):
    names = sorted(set(small_map) | set(big_map))
    rows = []
    for name in names:
        s = small_map.get(name, float("nan"))
        b = big_map.get(name, float("nan"))
        ratio = (b / s) if (not math.isnan(s) and not math.isnan(b) and s != 0) else float("nan")
        pct = ((b - s) / s * 100.0) if (not math.isnan(s) and not math.isnan(b) and s != 0) else float("nan")
        if math.isnan(pct):
            trend = "same"
        elif pct > 2.0:
            trend = "regressed"
        elif pct < -2.0:
            trend = "improved"
        else:
            trend = "same"
        rows.append({
            "function": name,
            "small_seconds": s,
            "big_seconds": b,
            "small_pretty": ("" if math.isnan(s) else human_time(s)),
            "big_pretty": ("" if math.isnan(b) else human_time(b)),
            "big/small": ratio,
            "% change (big vs small)": pct,
            "trend": trend,
        })
    return rows

def write_markdown(rows, out):
    rows_sorted = sorted(
        rows,
        key=lambda r: ({"regressed":0, "same":1, "improved":2}[r["trend"]],
                       -(r["% change (big vs small)"] or float("nan"))))
    print("| Function | Small (median) | Big (median) | big/small | % change | Trend |", file=out)
    print("|---|---:|---:|---:|---:|---|", file=out)
    for r in rows_sorted:
        bs = f'{r["big/small"]:.2f}' if r["big/small"]==r["big/small"] else "—"
        pct = f'{r["% change (big vs small)"]:.1f}%' if r["% change (big vs small)"]==r["% change (big vs small)"] else "—"
        print(f'| {r["function"]} | {r["small_pretty"]} | {r["big_pretty"]} | {bs} | {pct} | {r["trend"]} |', file=out)

def write_csv(rows, out):
    fieldnames = ["function","small_seconds","big_seconds","small_pretty","big_pretty","big/small","% change (big vs small)","trend"]
    w = csv.DictWriter(out, fieldnames=fieldnames)
    w.writeheader()
    for r in rows:
        w.writerow(r)

def main():
    ap = argparse.ArgumentParser(description="Compare two Criterion benchmark outputs (small vs big).")
    ap.add_argument("small_file", help="Path to small benchmark output text")
    ap.add_argument("big_file", help="Path to big benchmark output text")
    ap.add_argument("--out-md", help="Write a Markdown table to this path")
    ap.add_argument("--out-csv", help="Write a CSV table to this path")
    args = ap.parse_args()

    with open(args.small_file, "r", encoding="utf-8") as f:
        small_txt = f.read()
    with open(args.big_file, "r", encoding="utf-8") as f:
        big_txt = f.read()

    small_map = parse_bench(small_txt)
    big_map = parse_bench(big_txt)
    rows = compare(small_map, big_map)

    if not args.out_md and not args.out_csv:
        write_markdown(rows, sys.stdout)
    else:
        if args.out_md:
            with open(args.out_md, "w", encoding="utf-8") as out:
                write_markdown(rows, out)
        if args.out_csv:
            with open(args.out_csv, "w", encoding="utf-8", newline="") as out:
                write_csv(rows, out)

if __name__ == "__main__":
    main()

