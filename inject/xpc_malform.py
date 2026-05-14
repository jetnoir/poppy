#!/usr/bin/env python3
"""
Poppy V5 — xpc_malform.py

Client-side fault injector: spawns an ObjC helper (xpc_malform) that sends
malformed XPC messages to a target daemon's mach service, classifies the
reply, and logs daemon PID stability.

Uses an ObjC helper rather than ctypes to libxpc because:
  - arm64e xpc_object_t block dispatch is unreliable from ctypes
  - NSXPC/xpc macros rely on runtime state ctypes can't replicate

The helper is built automatically if missing.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HELPER_SRC = HERE / "xpc_malform.m"
HELPER_BIN = HERE / "xpc_malform"

# Daemon name → published mach services
DAEMON_SERVICES = {
    'tipsd':             ['com.apple.tipsd', 'com.apple.tipsd.assistant'],
    'donotdisturbd':     ['com.apple.donotdisturb.service',
                          'com.apple.donotdisturb.availability.service',
                          'com.apple.donotdisturb.appconfiguration.service',
                          'com.apple.aps.donotdisturb.sync-engine'],
    'replayd':           ['com.apple.replayd',
                          'com.apple.replaykit.sharingsession',
                          'com.apple.replayd-cache-delete'],
    'peopled':           ['com.apple.people.agent',
                          'com.apple.corespotlight.daemon.people'],
    'siriinferenced':    ['com.apple.siriinferenced',
                          'com.apple.siriinferenced.signals',
                          'com.apple.siriinferenced.remembers',
                          'com.apple.sirisuggestions'],
    'assistantd':        ['com.apple.assistant.client',
                          'com.apple.siri.external_request',
                          'com.apple.assistantd.managedstorage'],
    'BiomeAgent':        ['com.apple.biome.access.user',
                          'com.apple.biome.PublicStreamAccessService',
                          'com.apple.biome.compute.publisher.service.user',
                          'com.apple.biome.compute.source.user'],
    # Free-form: allow 'service=NAME' custom targets by using the daemon name literally
}

VARIANTS = ('empty', 'size', 'nest', 'type')


def ensure_helper():
    """Compile the ObjC helper binary if missing or out-of-date."""
    if HELPER_BIN.exists() and HELPER_BIN.stat().st_mtime > HELPER_SRC.stat().st_mtime:
        return
    print(f"[inject] building helper from {HELPER_SRC.name}", file=sys.stderr)
    cc = subprocess.run(
        ['clang', '-Wno-deprecated-declarations',
         '-framework', 'Foundation',
         str(HELPER_SRC), '-o', str(HELPER_BIN)],
        capture_output=True, text=True)
    if cc.returncode != 0:
        print(f"[inject] build FAILED:\n{cc.stderr}", file=sys.stderr)
        sys.exit(1)


def check_pid(daemon: str) -> int | None:
    try:
        out = subprocess.check_output(['pgrep', '-x', daemon], text=True).strip()
        return int(out.split()[0]) if out else None
    except Exception:
        return None


def send_one(service: str, variant: str, timeout: float = 3.0) -> dict:
    try:
        r = subprocess.run(
            [str(HELPER_BIN), service, variant],
            capture_output=True, text=True, timeout=timeout
        )
        out = r.stdout.strip() or r.stderr.strip()
        try:
            return json.loads(out)
        except Exception:
            return {'service': service, 'variant': variant,
                    'result': 'parse_fail', 'raw': out, 'rc': r.returncode}
    except subprocess.TimeoutExpired:
        return {'service': service, 'variant': variant, 'result': 'timeout'}


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--daemon', required=True,
                   help='Daemon name (for PID tracking + default services). Also accepts "service:NAME" for direct service targeting.')
    p.add_argument('--variants', default='all',
                   help='comma-separated: ' + ','.join(VARIANTS) + ' or "all"')
    p.add_argument('--out', default=None)
    args = p.parse_args()

    ensure_helper()

    # Services + PID target
    if args.daemon.startswith('service:'):
        services = [args.daemon.split(':', 1)[1]]
        pid_target = None
    else:
        services = DAEMON_SERVICES.get(args.daemon)
        if not services:
            print(f"[inject] no services mapped for daemon '{args.daemon}'", file=sys.stderr)
            print("Known daemons: " + ", ".join(DAEMON_SERVICES), file=sys.stderr)
            sys.exit(2)
        pid_target = args.daemon

    variants = list(VARIANTS) if args.variants == 'all' else [v for v in args.variants.split(',') if v in VARIANTS]

    pid0 = check_pid(pid_target) if pid_target else None
    results = []
    for v in variants:
        for s in services:
            r = send_one(s, v)
            if pid_target:
                cur = check_pid(pid_target)
                r['daemon_pid0']    = pid0
                r['daemon_pid_now'] = cur
                r['daemon_alive']   = cur is not None
                r['pid_unchanged']  = (cur == pid0)
            results.append(r)
            marker = ''
            if pid_target and not r.get('pid_unchanged', True):
                marker = '  ⚠ PID CHANGED (crash signal)'
            print(f"  {v:8s} {s:55s} -> {r['result']:12s}{marker}")

    out_path = args.out or f"/tmp/poppy_inject_{args.daemon}_{int(time.time())}.jsonl"
    with open(out_path, 'w') as fh:
        for r in results:
            fh.write(json.dumps(r) + '\n')
    print(f"\n[inject] log → {out_path}")

    if pid_target:
        changes = sum(1 for r in results if not r.get('pid_unchanged', True))
        print(f"[inject] daemon PID changes: {changes}  {'⚠ CRASH SIGNAL' if changes else '(stable)'}")


if __name__ == '__main__':
    main()
