#!/usr/bin/env python3
import sys
import re
import argparse
import math

UNIT_SCALE = {
    "ns": 1e-9,
    "us": 1e-6,
    "µs": 1e-6,
    "ms": 1e-3,
    "s": 1.0,
}

DOMAINS = ["domain11", "domain12", "domain16"]
DOMAIN_LABELS = {
    "domain11": "Domain11 (255)",
    "domain12": "Domain12 (767)",
    "domain16": "Domain16 (16127)",
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
    return sorted(vals)[len(vals)//2]

def parse_bench(text: str) -> dict:
    res = {}
    lines = text.splitlines()
    prev_nonempty = ""
    for line in lines:
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

def split_by_domain(bench_map: dict) -> dict:
    domains = {}
    for name, val in bench_map.items():
        parts = name.split('/', 1)
        if len(parts) == 2:
            domain = parts[0]
            bench_name = parts[1]
        else:
            domain = 'default'
            bench_name = name
        domains.setdefault(domain, {})[bench_name] = val
    return domains

def human_time(seconds: float) -> str:
    if seconds < 1e-6:
        return f"{seconds*1e9:.3f} ns"
    if seconds < 1e-3:
        return f"{seconds*1e6:.3f} µs"
    if seconds < 1:
        return f"{seconds*1e3:.3f} ms"
    return f"{seconds:.3f} s"

def collect_rows(domain_maps: dict) -> list:
    all_names = set()
    for m in domain_maps.values():
        all_names |= set(m.keys())
    names = sorted(all_names)

    rows = []
    for name in names:
        row = {"function": name}
        for domain in DOMAINS:
            val = domain_maps.get(domain, {}).get(name, float("nan"))
            row[domain] = val
        rows.append(row)
    return rows

def write_markdown(rows, out):
    headers = ["Function"] + [DOMAIN_LABELS[d] for d in DOMAINS]
    print("| " + " | ".join(headers) + " |", file=out)
    print("|---" + "|---:" * len(DOMAINS) + "|", file=out)
    for r in rows:
        cols = [r["function"]]
        for d in DOMAINS:
            v = r[d]
            cols.append("" if math.isnan(v) else human_time(v))
        print("| " + " | ".join(cols) + " |", file=out)

def main():
    ap = argparse.ArgumentParser(description="Display Criterion benchmark results for all ring domains.")
    ap.add_argument("file", help="Benchmark output file")
    ap.add_argument("--out-md", help="Write a Markdown table to this path")
    args = ap.parse_args()

    with open(args.file, "r", encoding="utf-8") as f:
        text = f.read()

    all_benches = parse_bench(text)
    domain_maps = split_by_domain(all_benches)

    for d in DOMAINS:
        if d not in domain_maps:
            print(f"Warning: no benchmarks found for '{d}'", file=sys.stderr)

    rows = collect_rows(domain_maps)

    if args.out_md:
        with open(args.out_md, "w", encoding="utf-8") as out:
            write_markdown(rows, out)
    else:
        write_markdown(rows, sys.stdout)

if __name__ == "__main__":
    main()
