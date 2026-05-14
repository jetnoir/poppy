#!/usr/bin/env python3
"""
Poppy V5 — coverage_diff.py

Diff two Poppy JSONL run files (calibration vs fault-injected). Emits a
per-symbol coverage delta — what fired in one run but not the other, and
counts of shared events.

Symbols are extracted from the `kind` field plus any `data.fn`/`data.sel`/
`data.key` fields present (matches the schemas emitted by xpc_observer.js,
trust_boundary.js, xpc_trace.d, entitlement.d).

Usage:
    python3 coverage_diff.py calibration.jsonl faulted.jsonl
    python3 coverage_diff.py calibration.jsonl faulted.jsonl --json out.json

Companion to: analysers/anomaly.py (single-run summariser).
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def load_events(path: Path):
    events = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            # tolerate non-JSON noise (DTrace ustack output, etc.)
            continue
    return events


def symbol_for(ev: dict) -> str:
    """Compose a stable symbol key from an event dict."""
    kind = ev.get('kind', '<no-kind>')
    data = ev.get('data') or {}
    if isinstance(data, dict):
        for k in ('sel', 'key', 'fn', 'cls'):
            if k in data and data[k]:
                return f'{kind}:{data[k]}'
    return kind


def count_symbols(events) -> Counter:
    return Counter(symbol_for(e) for e in events)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('calibration', type=Path,
                    help='Baseline run JSONL (no fault injection)')
    ap.add_argument('faulted', type=Path,
                    help='Fault-injected run JSONL')
    ap.add_argument('--json', type=Path, help='Optional JSON output path')
    args = ap.parse_args()

    cal = count_symbols(load_events(args.calibration))
    flt = count_symbols(load_events(args.faulted))

    only_cal = sorted(set(cal) - set(flt))
    only_flt = sorted(set(flt) - set(cal))
    shared   = sorted(set(cal) & set(flt))

    print(f'{"="*72}')
    print(f'Coverage diff')
    print(f'  calibration : {args.calibration} ({sum(cal.values())} events, {len(cal)} symbols)')
    print(f'  faulted     : {args.faulted} ({sum(flt.values())} events, {len(flt)} symbols)')
    print(f'{"="*72}\n')

    print(f'Symbols in CALIBRATION only ({len(only_cal)}):')
    for s in only_cal:
        print(f'  - {s}  (n={cal[s]})')

    print(f'\nSymbols in FAULTED only ({len(only_flt)}):  ← NEW CODE PATHS REACHED')
    for s in only_flt:
        print(f'  + {s}  (n={flt[s]})')

    print(f'\nShared symbols ({len(shared)}) with count delta:')
    deltas = sorted(((s, flt[s] - cal[s]) for s in shared),
                    key=lambda x: -abs(x[1]))
    for s, d in deltas[:30]:
        sign = '+' if d > 0 else ''
        print(f'  {sign}{d:>6}  {s}  (cal={cal[s]} → flt={flt[s]})')
    if len(deltas) > 30:
        print(f'  ... ({len(deltas)-30} more, see --json for full)')

    if args.json:
        payload = {
            'calibration': str(args.calibration),
            'faulted':     str(args.faulted),
            'cal_total':   sum(cal.values()),
            'flt_total':   sum(flt.values()),
            'only_calibration': dict((s, cal[s]) for s in only_cal),
            'only_faulted':     dict((s, flt[s]) for s in only_flt),
            'shared_deltas':    dict((s, flt[s] - cal[s]) for s in shared),
        }
        args.json.write_text(json.dumps(payload, indent=2, sort_keys=True))
        print(f'\n[*] JSON written to {args.json}')


if __name__ == '__main__':
    main()
