# Poppy — Troubleshooting

Common friction points encountered during research and how to resolve them.

## "Failed to attach" / Frida won't hook the target

**Symptoms:**
- `Failed to attach: unexpected error while building injector`
- `EXC_GUARD / THREAD_SET_STATE during attach`

**Most likely cause:** macOS hardening blocks Frida.

**Resolutions:**
1. **Check Frida version:** Ensure you are using the latest Frida version.
2. **Check boot-args:** Ensure `amfi_get_out_of_my_way=0x1` and `tss_should_crash=0` are set if running on bare metal.
3. **Use a SIP-disabled environment:** A VM with SIP fully disabled is the most reliable configuration.
4. **Fallback:** Use **DTrace + log-stream** if Frida remains blocked.

## DTrace silently produces no output

**Most likely cause:** Missing sudo. macOS DTrace requires root.

**Check:**
Run `id -u` (should be 0). Re-run your command with `sudo`.

## "0 crashes, parser robust" (The Black-Hole Problem)

**Symptom:** Your injector reports success, but the daemon shows no sign of processing the payload.

**Most likely cause:** Messages are being rejected by the NSXPC decoder (e.g., due to an "allowed classes" whitelist) before they reach the actual handler logic.

**Diagnostic:**
```sh
log stream --predicate 'process == "<daemon>"' --style compact --info
```
Look for "Allowed classes" exceptions or "Exception caught during decoding" messages in the system log.

## Daemon is wedged after a run

**Most likely cause:** Resource leak or inconsistent state after heavy fault injection.

**Recovery:**
- On SIP-disabled environments: `sudo launchctl kickstart -k system/<service>`.
- On SIP-enabled environments: A reboot may be required if `kickstart` is restricted.

**Mitigation:**
- Cap iteration counts.
- Ensure children are reaped in the injector.
- Add small delays between injections.

## Frida agent says "miss: <symbol>"

**Most likely cause:** Symbol inlining or name changes between macOS versions.

**Check:**
Use `Module.findExportByName(null, 'sym')` to search all loaded modules. For Objective-C, use `ObjC.classes.<Class>['- selector']` instead of raw export lookups.

## JSONL has lines that won't parse

**Most likely cause:** DTrace `ustack()` output or other non-JSON text mixed in.

**Fix:** Ensure your analysers use `try/except` when parsing lines with `json.loads()`.

## See Also
- `README.md` — Overview.
- `USER_GUIDE.md` — Recipes.
- `OPS_MANUAL.md` — Operational details.
