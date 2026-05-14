#!/usr/bin/env python3
"""
Poppy V5 — anomaly.py

Parses a JSONL trace from a Poppy run (Frida side) and surfaces:
  - Which entitlements the daemon checked
  - Which connections were accepted vs rejected, and for which client PIDs
  - Any Swift fatalError fires (the IntelPCore / SECD-01 pattern)
  - Any CFGetTypeID calls on suspicious objects (rare — sampled 1/1000)

Usage:
    python3 anomaly.py runs/poppy_tipsd_YYYYMMDD_HHMMSS.jsonl
    python3 anomaly.py runs/poppy_tipsd_*.jsonl   # aggregate multiple runs

Output: readable human summary + optional --json full report.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path


def load_runs(paths):
    events = []
    for p in paths:
        for line in Path(p).read_text().splitlines():
            if not line.strip():
                continue
            try:
                events.append((p, json.loads(line)))
            except json.JSONDecodeError:
                pass
    return events


def summarise(events):
    by_kind = Counter(e['kind'] for _, e in events)
    entitlement_checks = Counter()
    entitlement_for_client = defaultdict(set)
    connection_accepts = []
    connection_rejects = []
    fatals = []
    fridaerrs = []

    for _, e in events:
        kind = e['kind']
        d    = e.get('data', e)
        if kind == 'sec.entitlement.check':
            key = d.get('key') or '(null)'
            entitlement_checks[key] += 1
            entitlement_for_client[key].add(d.get('value') or '(null)')
        elif kind == 'xpc.shouldAcceptNewConnection':
            if d.get('accepted'):
                connection_accepts.append(d)
            else:
                connection_rejects.append(d)
        elif kind == 'swift.fatalError':
            fatals.append(d)
        elif kind == 'frida.error':
            fridaerrs.append(e)

    return {
        'by_kind':              by_kind,
        'entitlements':         entitlement_checks,
        'connection_accepts':   connection_accepts,
        'connection_rejects':   connection_rejects,
        'fatals':               fatals,
        'frida_errors':         fridaerrs,
    }


def print_summary(s: dict, full_json: bool = False):
    print('─' * 70)
    print(f"Events by kind ({sum(s['by_kind'].values())} total):")
    for k, c in s['by_kind'].most_common():
        print(f"  {k:45s} {c}")

    print()
    print(f"Entitlement checks:")
    if not s['entitlements']:
        print("  (none observed)")
    for k, c in s['entitlements'].most_common():
        print(f"  {c:>5d}× {k}")

    print()
    print(f"XPC connection acceptance:")
    print(f"  accepted: {len(s['connection_accepts'])}")
    print(f"  rejected: {len(s['connection_rejects'])}")
    if s['connection_accepts']:
        print("  accepted clients (sample):")
        for c in s['connection_accepts'][:5]:
            print(f"    pid={c.get('client_pid')} euid={c.get('effective_uid')} delegate={c.get('delegate')}")

    if s['fatals']:
        print()
        print(f"⚠ Swift fatalError fires:")
        for f in s['fatals']:
            print(f"   {f.get('symbol')}: {f.get('message')}")

    if s['frida_errors']:
        print()
        print(f"⚠ Frida agent errors ({len(s['frida_errors'])}):")
        for e in s['frida_errors'][:5]:
            d = e.get('data', e)
            print(f"   {d.get('description') or d.get('err')}")

    if full_json:
        print('\n── Full JSON ──')
        print(json.dumps({
            'by_kind':            dict(s['by_kind']),
            'entitlements':       dict(s['entitlements']),
            'accepts_count':      len(s['connection_accepts']),
            'rejects_count':      len(s['connection_rejects']),
            'fatals_count':       len(s['fatals']),
            'frida_errors_count': len(s['frida_errors']),
        }, indent=2))


def main():
    p = argparse.ArgumentParser()
    p.add_argument('paths', nargs='+', help='JSONL trace file(s) from poppy run')
    p.add_argument('--json', action='store_true', help='print full JSON summary')
    args = p.parse_args()

    events = load_runs(args.paths)
    if not events:
        print("(no events)", file=sys.stderr)
        sys.exit(1)

    s = summarise(events)
    print_summary(s, full_json=args.json)


if __name__ == '__main__':
    main()
