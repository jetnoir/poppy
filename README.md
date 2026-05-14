# Poppy — Dynamic Instrumentation Pipeline for macOS Security Research

Poppy is a toolkit for dynamic analysis, observability, and fault injection on macOS daemons and XPC services. It combines Frida instrumentation, DTrace probes, and custom injectors to provide a unified view of daemon behavior.

## Why

Static analysis on modern macOS (arm64e) daemons faces significant challenges:
- PAC (Pointer Authentication Codes) can obscure static call graphs.
- Swift and Objective-C dynamic dispatch are often invisible to traditional static analysis tools.

Dynamic analysis observes what actually happens at runtime:
- Which XPC handlers are invoked.
- Which entitlement checks gate specific actions.
- Code paths reached by specific inputs.
- Where faulted inputs cause deviations or crashes.

## Project Structure

```
poppy/
├── agents/               # Frida JS agents (run inside target process)
│   ├── xpc_observer.js      — NSXPCListener and handler dispatch tracer
│   ├── trust_boundary.js    — CFGetTypeID, CFDictionaryGetValue, SecTask* tracer
│   └── objc_probe.js        — Selective Objective-C message probing
├── scripts/              # DTrace scripts
│   ├── xpc_trace.d          — Mach message and XPC dispatch tracer
│   ├── entitlement.d        — Entitlement check monitor
│   └── crash_witness.d      — Process exit and crash capturer
├── inject/               # Fault injectors (client side)
│   ├── xpc_malform.py       — Raw XPC message malformer
│   └── nsxpc_fuzz.py        — NSXPC-level type confusion fuzzer
├── analysers/            # Trace post-processing tools
│   ├── anomaly.py           — Detects deviations from baseline runs
│   ├── coverage_diff.py     — Basic-block coverage diffing
│   └── entitlement_map.py   — Correlates services with checked entitlements
├── runs/                 # Directory for run logs (gitignored)
└── poppy.py              # Main orchestrator
```

## Usage

### 1. Observe a daemon
Capture XPC traffic and entitlement checks for a specified duration.
```bash
sudo python3 poppy.py run --daemon tipsd --duration 60
```

### 2. Fault injection
Send malformed XPC messages while observing the daemon's response.
```bash
sudo python3 poppy.py inject --daemon tipsd --variants all
```

### 3. Analyze results
Summarize a trace for interesting events or anomalies.
```bash
python3 analysers/anomaly.py runs/poppy_tipsd_*.jsonl
```

### 4. Entitlement mapping
Build a map of which daemons check which entitlements across multiple runs.
```bash
python3 analysers/entitlement_map.py runs/poppy_*.jsonl --md > entitlements.md
```

## Philosophy

- **Observe before perturbing:** Understand normal behavior before injecting faults.
- **Calibration is key:** Record a baseline trace to compare against experimental runs.
- **Unified Format:** Everything is logged as JSONL for easy consumption by downstream tools.
- **Leverage Proven Tools:** Built on top of Frida and DTrace for reliability.

## Dependencies

- **Frida:** `pip install frida-tools`
- **PySide6:** (For GUI) `pip install PySide6`
- **PyObjC:** (Optional, for enhanced XPC fuzzing) `pip install pyobjc-core pyobjc-framework-Cocoa`
- **DTrace:** Built-in to macOS (requires root and usually SIP disabled).

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
