# Poppy — User Guide

How to use Poppy for a daemon-audit campaign. Companion to README.md (overview), OPS_MANUAL.md (operations), and the inline docstrings in each component.

## The Mental Model

```
   ┌─────────────────────┐    ┌─────────────────────┐
   │   YOUR ATTACKER     │    │   TARGET DAEMON     │
   │                     │    │                     │
   │  inject/*.py  ──────┼──► │  Frida agents       │
   │  (fault sender)     │    │  + DTrace scripts   │
   │                     │    │  (observers)        │
   └─────────┬───────────┘    └──────────┬──────────┘
             │                            │
             └─────►  runs/*.jsonl  ◄─────┘
                             │
                             ▼
                     analysers/*.py
                   (anomaly, diff, map)
```

Three things happen in parallel:
1. **Fault** — your client (xpc_malform / nsxpc_fuzz) sends a malformed payload.
2. **Observe** — Frida agents in the target daemon log handler dispatch and entitlement checks; DTrace logs syscalls.
3. **Analyse** — JSONL logs are consumed by analysers to compare runs, build maps, and surface anomalies.

## Quick Recipes

### Recipe 1 — observe a daemon for a fixed window
Capture XPC traffic, entitlement checks, and Swift fatalErrors for 60 seconds.

```sh
sudo python3 poppy.py run --daemon <daemonname> --duration 60
# Outputs runs/poppy_<daemonname>_<timestamp>.jsonl
```

Then summarise:
```sh
python3 analysers/anomaly.py runs/poppy_<daemonname>_*.jsonl
```

### Recipe 2 — calibration vs fault-injected diff
Run the daemon once normally to establish baseline coverage, then again under your fault payload, then diff:

```sh
# baseline (no fault injection — just normal stimulus)
sudo python3 poppy.py run --daemon fskitd --duration 60
# rename the output for clarity, e.g., runs/poppy_fskitd_baseline.jsonl

# faulted (your malformed payload running concurrently)
sudo python3 poppy.py run --daemon fskitd --duration 60 &
python3 inject/xpc_malform.py --service com.apple.filesystems.fskitd
# results in runs/poppy_fskitd_faulted.jsonl

# diff
python3 analysers/coverage_diff.py runs/poppy_fskitd_baseline.jsonl runs/poppy_fskitd_faulted.jsonl
```

### Recipe 3 — entitlement map across multiple daemons
After several Poppy runs:

```sh
python3 analysers/entitlement_map.py runs/poppy_*.jsonl --md > entitlements.md
```

### Recipe 4 — focused selector probe (objc_msgSend)
When you want to know exactly which selectors of a specific class are firing:

```sh
POPPY_OBJC_CLASSES="FSClient,fskitdXPCServer" \
    frida -p $(pgrep fskitd) -l agents/objc_probe.js
```

## Component Reference

### Frida agents (in-process JS)
| File | Hooks | When to use |
|------|-------|-------------|
| `agents/xpc_observer.js` | NSXPCListener accept, send_message, SecTask, Swift fatalError | Default for any daemon audit |
| `agents/trust_boundary.js` | CFGetTypeID (sampled), CFDictionaryGetValue, SecTask*, xpc_dictionary_get_* | Type-confusion or trust-boundary probing |
| `agents/objc_probe.js` | objc_msgSend (allow-listed via env) | Targeted selector tracing |

### DTrace scripts (root required)
| File | Probes | When to use |
|------|--------|-------------|
| `scripts/xpc_trace.d` | xpc_*, SecTask*, CF asserts | Initial daemon profile |
| `scripts/entitlement.d` | SecTaskCopyValueForEntitlement only | Confirming entitlement gates |
| `scripts/crash_witness.d` | proc:::exit pattern-matched | Catch incidental crashes |

### Injectors (client-side)
| File | Layer | When to use |
|------|-------|-------------|
| `inject/xpc_malform.py` | Raw libxpc | Test daemon's libxpc-layer robustness |
| `inject/nsxpc_fuzz.py` | NSXPC abstraction | Test allowed-classes whitelist enforcement |

### Analysers (offline post-processing)
| File | Output | When to use |
|------|--------|-------------|
| `analysers/anomaly.py` | Human-readable summary | First pass on any single run |
| `analysers/coverage_diff.py` | Per-symbol delta | After paired calibration/faulted runs |
| `analysers/entitlement_map.py` | Markdown entitlement table | After multiple daemon runs |

## JSONL Event Schema

Every Poppy event has this shape:

```json
{ "ts": <ms epoch>,
  "pid": <int>,
  "kind": "<event-kind-string>",
  "data": { ... event-specific ... }
}
```

Common `kind` values: `agent.start`, `dtrace.begin`, `xpc.send`, `sec.entitlement`, `proc.exit`.

## See Also
- `README.md` — Overview and setup.
- `OPS_MANUAL.md` — Operational details and privileges.
- `TROUBLESHOOTING.md` — Common issues and resolutions.
