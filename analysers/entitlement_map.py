#!/usr/bin/env python3
"""
Poppy V5 — entitlement_map.py

Aggregates one or more Poppy JSONL run files into a per-daemon table of
which entitlements were checked, how often, and how often they were
granted (return-pointer non-null).

Reads events with kind == 'sec.entitlement' from xpc_observer.js,
trust_boundary.js, or entitlement.d.

Usage:
    python3 entitlement_map.py runs/poppy_*.jsonl
    python3 entitlement_map.py runs/poppy_*.jsonl --md  > entitlements.md
    python3 entitlement_map.py runs/poppy_*.jsonl --json > entitlements.json

Companion to: analysers/anomaly.py, analysers/coverage_diff.py.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path


def load_events(paths):
    all_events = []
    for p in paths:
        path = Path(p)
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
                ev['_source'] = path.name
                all_events.append(ev)
            except json.JSONDecodeError:
                continue
    return all_events


def daemon_from_source(name: str) -> str:
    """Heuristic: poppy_DAEMON_TIMESTAMP.* → DAEMON."""
    parts = name.split('_')
    if len(parts) >= 3 and parts[0] in ('poppy', 'orch'):
        return parts[1]
    return name


def build_map(events):
    """daemon -> {entitlement_key: {checks, grants}}"""
    m = defaultdict(lambda: defaultdict(lambda: {'checks': 0, 'grants': 0}))
    for ev in events:
        if ev.get('kind') != 'sec.entitlement':
            continue
        daemon = daemon_from_source(ev.get('_source', '<unknown>'))
        data = ev.get('data') or {}
        key = data.get('key') or ev.get('cfstr_ptr') or '<unknown>'
        m[daemon][key]['checks'] += 1
        if data.get('granted') or ev.get('granted'):
            m[daemon][key]['grants'] += 1
    return m


def render_text(m):
    out = []
    for daemon in sorted(m):
        out.append(f'\n=== {daemon} ===')
        rows = sorted(m[daemon].items(), key=lambda x: -x[1]['checks'])
        for key, stats in rows:
            rate = (stats['grants'] / stats['checks'] * 100) if stats['checks'] else 0
            out.append(f'  {stats["grants"]:>4}/{stats["checks"]:<4}  {rate:5.1f}%  {key}')
    return '\n'.join(out) + '\n'


def render_md(m):
    out = ['# Entitlement Map\n']
    for daemon in sorted(m):
        out.append(f'## `{daemon}`\n')
        out.append('| Entitlement | Granted | Checks | Rate |')
        out.append('|-------------|--------:|-------:|-----:|')
        rows = sorted(m[daemon].items(), key=lambda x: -x[1]['checks'])
        for key, stats in rows:
            rate = (stats['grants'] / stats['checks'] * 100) if stats['checks'] else 0
            out.append(f'| `{key}` | {stats["grants"]} | {stats["checks"]} | {rate:.1f}% |')
        out.append('')
    return '\n'.join(out)


def render_json(m):
    return json.dumps(
        {d: {k: dict(v) for k, v in keys.items()} for d, keys in m.items()},
        indent=2, sort_keys=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('runs', nargs='+', help='One or more Poppy JSONL run files')
    g = ap.add_mutually_exclusive_group()
    g.add_argument('--md', action='store_true', help='Markdown output')
    g.add_argument('--json', action='store_true', help='JSON output')
    args = ap.parse_args()

    events = load_events(args.runs)
    m = build_map(events)
    if not m:
        print('[!] no sec.entitlement events found in supplied runs', file=sys.stderr)
        sys.exit(1)

    if args.md:
        print(render_md(m))
    elif args.json:
        print(render_json(m))
    else:
        print(render_text(m))


if __name__ == '__main__':
    main()
