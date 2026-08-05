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

DURATION_RE = re.compile(r"([0-9]*\.?[0-9]+)\s*(ns|us|µs|μs|ms|s)\b")

# Benchmarks that are deliberately not run for some domains, and the domains they are
# absent from. Without this, an intentional omission is indistinguishable from a run that
# died partway through, and --strict refuses to publish a table that is in fact complete.
#
# Keep in sync with `batch_sizes_for` in `benches/verifiable_validate.rs`; an entry here
# only says a gap is allowed, so a benchmark listed but still measured is not an error.
EXPECTED_GAPS = {
    # Every proof in the batch needs its own `open`, which is seconds at domain16, so
    # 1024 of them is roughly 45 minutes of untimed setup. See LARGE_SINGLE_RING_BATCH.
    "batch_validate/single_ring/1024": {"domain16"},
}

def extract_estimate_from_brackets(bracket_str: str) -> float:
    """Return the point estimate from a Criterion `time: [lower estimate upper]` bracket.

    Criterion always prints exactly three durations in ascending order, so the estimate
    is the middle one. Insisting on three rather than accepting whatever parses means a
    change in Criterion's output format surfaces as a loud failure instead of silently
    yielding a confidence bound in place of the estimate.
    """
    found = DURATION_RE.findall(bracket_str)
    if len(found) != 3:
        raise ValueError(
            f"expected 3 durations (lower estimate upper), found {len(found)}: {bracket_str!r}"
        )
    value, unit = found[1]
    return float(value) * UNIT_SCALE[unit.replace("μ", "µ")]

def parse_bench(text: str) -> tuple:
    """Parse benchmark name -> seconds, plus a list of things that could not be parsed.

    Criterion emits either `name  time: [...]` on one line, or, when the name is long,
    the bare name on its own line followed by an indented `time: [...]`. The second form
    is why `prev_nonempty` is tracked: the name always immediately precedes the timing.
    """
    res = {}
    problems = []
    lines = text.splitlines()
    prev_nonempty = ""
    for line in lines:
        m = re.match(r"^([^\s].*?)\s+time:\s+\[(.*?)\]", line)
        if m:
            name = m.group(1).strip()
            bracket = m.group(2)
            try:
                res[name] = extract_estimate_from_brackets(bracket)
            except Exception as exc:
                problems.append(f"{name}: {exc}")
            prev_nonempty = name
            continue
        if "time:" in line:
            m2 = re.search(r"time:\s+\[(.*?)\]", line)
            if m2 and prev_nonempty:
                name = prev_nonempty.strip()
                bracket = m2.group(1)
                try:
                    res[name] = extract_estimate_from_brackets(bracket)
                except Exception as exc:
                    problems.append(f"{name}: {exc}")
                continue
        stripped = line.strip()
        if stripped:
            prev_nonempty = stripped
    return res, problems

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

def natural_key(name: str):
    # Sort embedded integers numerically so batch_validate/8 precedes batch_validate/128.
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", name)]

def collect_rows(domain_maps: dict) -> list:
    all_names = set()
    for m in domain_maps.values():
        all_names |= set(m.keys())
    names = sorted(all_names, key=natural_key)

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
    ap.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero if any timing failed to parse or any domain is missing or "
             "incompletely covered. Use when the output will be published.",
    )
    args = ap.parse_args()

    with open(args.file, "r", encoding="utf-8") as f:
        text = f.read()

    all_benches, problems = parse_bench(text)
    domain_maps = split_by_domain(all_benches)

    # Report everything that does not make it into the table. Left silent, a partly
    # broken run yields a plausible-looking table with no hint that anything is missing.
    # Without --strict these are reported and the table is still printed, so a human can
    # see what did come through; --strict turns them into a refusal to publish.
    suspect = False

    for problem in problems:
        print(f"error: unparsable timing: {problem}", file=sys.stderr)
        suspect = True

    dropped = sorted(
        name
        for domain, benches in domain_maps.items()
        if domain not in DOMAINS
        for name in benches
    )
    if dropped:
        # Expected for any benchmark not named `<domain>/...` — `ed25519_verify` is one.
        # Listed rather than hidden so an accidentally misnamed benchmark is visible.
        print(
            f"note: {len(dropped)} benchmark(s) not in any ring domain, excluded from the "
            f"table: {', '.join(dropped)}",
            file=sys.stderr,
        )

    missing_domains = [d for d in DOMAINS if not domain_maps.get(d)]
    for d in missing_domains:
        print(f"warning: no benchmarks found for '{d}'", file=sys.stderr)
    if missing_domains:
        suspect = True

    rows = collect_rows(domain_maps)

    # A benchmark present for some domains but not others means that domain's run did
    # not get that far. Names present in *no* domain are the `dropped` case reported
    # above (they still get a blank row), not partial coverage.
    covered = [d for d in DOMAINS if domain_maps.get(d)]
    incomplete = []
    for r in rows:
        allowed = EXPECTED_GAPS.get(r["function"], frozenset())
        gaps = [d for d in covered if math.isnan(r[d]) and d not in allowed]
        if gaps and len(gaps) < len(covered):
            incomplete.append((r["function"], gaps))
    for name, gaps in incomplete:
        print(
            f"warning: '{name}' missing for {', '.join(gaps)}",
            file=sys.stderr,
        )
    if incomplete:
        suspect = True

    if suspect and args.strict:
        print(
            "error: refusing to report a partial table (--strict)",
            file=sys.stderr,
        )
        return 1

    if args.out_md:
        with open(args.out_md, "w", encoding="utf-8") as out:
            write_markdown(rows, out)
    else:
        write_markdown(rows, sys.stdout)
    return 0

if __name__ == "__main__":
    sys.exit(main())
