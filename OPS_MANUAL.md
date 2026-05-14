# Poppy — Ops Manual

Operational notes for running Poppy. Covers privileges, hardware/OS considerations, and run hygiene.

## Required Privileges

| Component | Privilege | Reason |
|-----------|-----------|--------|
| Frida agents | sudo (usually) | Attaching to system daemons requires root. |
| DTrace scripts | **sudo always** | DTrace requires root on macOS. |
| Injectors | User/Sudo | Depends on the target Mach service's accessibility. |
| Analysers | None | Pure offline post-processing. |

`poppy.py run` will skip DTrace when launched without sudo.

## Environment Setup

### System Integrity Protection (SIP)
Default macOS state blocks Frida from attaching to system processes. You have two main options:

1. **Research VM with SIP disabled:** Recommended for full capability.
2. **Research Machine with specific boot-args:** `amfi_get_out_of_my_way=0x1` and `tss_should_crash=0`. Note that some hardened daemons may still resist attachment.

If Frida is blocked, fall back to **DTrace + log-stream** observation.

## DTrace Considerations

- **pid-provider:** Use the pid-provider for reliable symbol hooking.
- **Destructive option:** `pragma D option destructive` is required for many of our scripts to properly format output.
- **PAC Influence:** On arm64e, `ustack()` may return incomplete frames due to Pointer Authentication.

## Run Hygiene

### Naming Convention
Files in `runs/` follow `poppy_<daemon>_<YYYYMMDD>_<HHMMSS>.*`. The orchestrator handles this automatically.

### Cleanup
The `runs/` directory is gitignored. Periodically prune old trace files to save space:
```sh
find runs/ -name '*.jsonl' -mtime +30 -delete
```

## System Limits

Heavy injection runs can hit system-level limits:
- **`kern.maxprocperuid`:** Ensure injector children are reaped to avoid hitting process limits.
- **File Descriptors:** Some daemons may leak descriptors under heavy fault; monitor with `lsof`.
- **Memory Pressure:** Monitor for leaked helper processes that can consume significant RAM.

## See Also
- `README.md` — Overview.
- `USER_GUIDE.md` — Recipes and component reference.
- `TROUBLESHOOTING.md` — Common friction points.
