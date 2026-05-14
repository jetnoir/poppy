#!/usr/bin/env python3
"""
Poppy V5 — main orchestrator for dynamic daemon audit.

Commands:
    poppy.py run    --daemon NAME  [--duration SECS]  [--no-frida] [--no-dtrace]
    poppy.py inject --daemon NAME  [--variants all|type|size|nest|empty]
    poppy.py enum                                    List running Apple daemons + XPC services
    poppy.py attach --pid PID                        Attach Frida agents to existing PID

All runs emit JSONL to runs/poppy_<daemon>_<ts>.jsonl plus side-channel DTrace
logs in the same prefix.
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

POPPY_DIR = Path(__file__).resolve().parent
AGENT_DIR = POPPY_DIR / "agents"
DTRACE_DIR = POPPY_DIR / "scripts"
RUNS_DIR   = POPPY_DIR / "runs"
RUNS_DIR.mkdir(parents=True, exist_ok=True)


# ── Daemon discovery ──────────────────────────────────────────────────────────

def find_running_daemon(name: str) -> int | None:
    """pgrep for daemon name, return PID (or None)."""
    try:
        out = subprocess.check_output(['pgrep', '-x', name], text=True).strip()
        return int(out.split()[0]) if out else None
    except subprocess.CalledProcessError:
        return None


def find_daemon_binary(name: str) -> str | None:
    """Find the on-disk path for a daemon executable by name."""
    pid = find_running_daemon(name)
    if pid:
        try:
            out = subprocess.check_output(['ps', '-p', str(pid), '-o', 'comm='], text=True)
            return out.strip()
        except subprocess.CalledProcessError:
            pass
    # Fallback: launchd plist lookup
    for root in ('/System/Library/LaunchDaemons', '/System/Library/LaunchAgents'):
        plist = Path(root) / f"com.apple.{name}.plist"
        if plist.exists():
            try:
                return subprocess.check_output(
                    ['plutil', '-extract', 'Program', 'raw', str(plist)],
                    text=True, stderr=subprocess.DEVNULL
                ).strip() or subprocess.check_output(
                    ['plutil', '-extract', 'ProgramArguments.0', 'raw', str(plist)],
                    text=True, stderr=subprocess.DEVNULL
                ).strip()
            except subprocess.CalledProcessError:
                continue
    return None


# ── Frida session ─────────────────────────────────────────────────────────────

def run_frida(pid: int, agent_path: Path, out_path: Path, duration: int):
    """Attach Frida, load agent, stream messages to JSONL."""
    import frida

    print(f"[poppy] frida attach pid={pid} agent={agent_path.name}")
    session = frida.attach(pid)
    src = agent_path.read_text()
    script = session.create_script(src)

    with open(out_path, 'a') as fh:
        def on_message(msg, data):
            if msg.get('type') == 'send':
                fh.write(json.dumps(msg['payload']) + '\n')
                fh.flush()
            elif msg.get('type') == 'error':
                fh.write(json.dumps({
                    'kind': 'frida.error',
                    'description': msg.get('description'),
                    'stack':       msg.get('stack'),
                }) + '\n')
                fh.flush()

        script.on('message', on_message)
        script.load()
        print(f"[poppy] agent loaded, observing for {duration}s → {out_path}")
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            print("[poppy] interrupted")
        script.unload()
        session.detach()


# ── DTrace side-channel ───────────────────────────────────────────────────────

def start_dtrace(pid: int, script: Path, out_path: Path):
    """Start DTrace in background, logging to out_path."""
    if os.geteuid() != 0:
        print("[poppy] dtrace requires root — skipping DTrace (use sudo for full run)")
        return None
    fh = open(out_path, 'w')
    # NB: SIP must be disabled on the target for pid provider on system binaries
    # -Z allows probe descriptions that match zero probes (fn/libs not in target)
    proc = subprocess.Popen(
        ['dtrace', '-Z', '-q', '-s', str(script), '-p', str(pid)],
        stdout=fh, stderr=subprocess.STDOUT
    )
    print(f"[poppy] dtrace started pid={proc.pid} → {out_path}")
    return proc


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_run(args):
    daemon = args.daemon
    pid = find_running_daemon(daemon)
    if not pid:
        print(f"[poppy] daemon '{daemon}' not running — start it first")
        sys.exit(2)

    ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
    prefix = RUNS_DIR / f"poppy_{daemon}_{ts}"
    frida_out  = prefix.with_suffix('.jsonl')
    dtrace_out = prefix.with_suffix('.dtrace.jsonl')

    # Manifest
    manifest = {
        'ts':       ts,
        'daemon':   daemon,
        'pid':      pid,
        'duration': args.duration,
        'binary':   find_daemon_binary(daemon),
        'uname':    subprocess.check_output(['uname', '-a'], text=True).strip(),
    }
    (prefix.with_suffix('.manifest.json')).write_text(json.dumps(manifest, indent=2))
    print(f"[poppy] manifest → {prefix.with_suffix('.manifest.json')}")

    # DTrace side-channel
    dtrace_proc = None
    if not args.no_dtrace:
        dtrace_proc = start_dtrace(pid, DTRACE_DIR / 'xpc_trace.d', dtrace_out)

    # Frida main channel
    if not args.no_frida:
        run_frida(pid, AGENT_DIR / 'xpc_observer.js', frida_out, args.duration)
    else:
        time.sleep(args.duration)

    if dtrace_proc:
        dtrace_proc.terminate()
        dtrace_proc.wait(timeout=5)

    print(f"[poppy] run complete — {prefix}.*")


def cmd_enum(args):
    """Enumerate daemons with XPC mach services."""
    candidates = [
        'assistantd', 'tipsd', 'peopled', 'siriinferenced', 'donotdisturbd',
        'replayd', 'appstoreagent', 'progressd', 'callintelligenced',
        'intelligenceflowd', 'intelligencecontextd', 'intelligenceplatformd',
        'intelligencetasksd', 'biomed', 'biomesyncd', 'avconferenced',
    ]
    print(f"{'Daemon':30s} {'PID':>8s}  {'Binary'}")
    print('─' * 100)
    for d in candidates:
        pid = find_running_daemon(d)
        binp = find_daemon_binary(d) or '(not found)'
        print(f"{d:30s} {str(pid or '-'):>8s}  {binp}")


def cmd_attach(args):
    ts  = datetime.now().strftime('%Y%m%d_%H%M%S')
    pid = args.pid
    prefix = RUNS_DIR / f"poppy_pid{pid}_{ts}"
    run_frida(pid, AGENT_DIR / 'xpc_observer.js', prefix.with_suffix('.jsonl'), args.duration)


def cmd_inject(args):
    """Run the injector alongside an observe session."""
    # Defer to inject/xpc_malform.py
    from subprocess import run as _run
    cmd = ['python3', str(POPPY_DIR / 'inject' / 'xpc_malform.py'),
           '--daemon', args.daemon,
           '--variants', args.variants]
    print(f"[poppy] exec: {' '.join(cmd)}")
    _run(cmd, check=False)


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(prog='poppy', description='V5 dynamic daemon audit')
    sub = p.add_subparsers(dest='cmd', required=True)

    pr = sub.add_parser('run',     help='Observe a running daemon')
    pr.add_argument('--daemon', required=True)
    pr.add_argument('--duration', type=int, default=60)
    pr.add_argument('--no-frida',  action='store_true')
    pr.add_argument('--no-dtrace', action='store_true')
    pr.set_defaults(func=cmd_run)

    pe = sub.add_parser('enum', help='List Apple daemons + whether running')
    pe.set_defaults(func=cmd_enum)

    pa = sub.add_parser('attach', help='Attach by PID')
    pa.add_argument('--pid', type=int, required=True)
    pa.add_argument('--duration', type=int, default=60)
    pa.set_defaults(func=cmd_attach)

    pi = sub.add_parser('inject', help='Send malformed XPC messages')
    pi.add_argument('--daemon',   required=True)
    pi.add_argument('--variants', default='all')
    pi.set_defaults(func=cmd_inject)

    args = p.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
