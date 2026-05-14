#!/usr/sbin/dtrace -s
/*
 * Poppy V5 — xpc_trace.d
 *
 * DTrace observing XPC + security activity on a target PID.
 * Uses ONLY pid-provider probes (macOS 26 has syscall:: provider stripped
 * to 4 probes on this kernel build — pid-provider is the reliable surface).
 *
 * Usage:
 *   sudo dtrace -s xpc_trace.d -p <pid>
 */

#pragma D option quiet
#pragma D option destructive
#pragma D option strsize=512

dtrace:::BEGIN
{
    printf("{\"ts\":%d,\"kind\":\"dtrace.begin\"}\n", walltimestamp / 1000000);
}

/* ── xpc_connection_send_message / _with_reply ──────────────────────────── */
pid$target::xpc_connection_send_message:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"xpc.send\"}\n",
           walltimestamp / 1000000, pid);
}

pid$target::xpc_connection_send_message_with_reply:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"xpc.send_reply\"}\n",
           walltimestamp / 1000000, pid);
}

pid$target::xpc_connection_send_message_with_reply_sync:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"xpc.send_reply_sync\"}\n",
           walltimestamp / 1000000, pid);
}

/* ── xpc_connection_resume (connection activated) ───────────────────────── */
pid$target::xpc_connection_resume:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"xpc.conn_resume\",\"conn\":0x%x}\n",
           walltimestamp / 1000000, pid, arg0);
}

/* ── Swift XPC error handlers (fire when client connection is rejected/torn down) ─ */
pid$target:libswiftXPC.dylib:_swift_xpc_connection_interrupted:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"swift.xpc.interrupted\"}\n",
           walltimestamp / 1000000, pid);
}

pid$target:libswiftXPC.dylib:_swift_xpc_connection_invalid:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"swift.xpc.invalid\"}\n",
           walltimestamp / 1000000, pid);
}

pid$target:libswiftXPC.dylib:_swift_xpc_connection_error_peer_code_signing_requirement:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"swift.xpc.codesign_fail\"}\n",
           walltimestamp / 1000000, pid);
}

/* NOTE: NSXPCListener -listener:shouldAcceptNewConnection: lives as ObjC method
 * and requires the objc$target provider (not pid$target). The Frida agent
 * handles that selector. DTrace covers the C-level path. */

/* ── xpc_connection_set_event_handler ───────────────────────────────────── */
pid$target::xpc_connection_set_event_handler:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"xpc.listen_register\"}\n",
           walltimestamp / 1000000, pid);
}

/* ── SecTaskCopyValueForEntitlement (the entitlement gate) ──────────────── */
/* arg1 is a CFStringRef (CoreFoundation string object), NOT a C string.
 * copyinstr would produce garbage — we log the pointer so Frida-side + post
 * analysis can deref. Frida agent xpc_observer.js resolves the NSString. */
pid$target::SecTaskCopyValueForEntitlement:entry
{
    self->ent_cfstr = arg1;
    self->ent_ts    = timestamp;
}

pid$target::SecTaskCopyValueForEntitlement:return
/self->ent_ts/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"sec.entitlement\",\"cfstr_ptr\":\"0x%lx\",\"ret_ptr\":\"0x%lx\",\"granted\":%d,\"us\":%d}\n",
           walltimestamp / 1000000, pid,
           self->ent_cfstr, arg1, arg1 != 0 ? 1 : 0,
           (timestamp - self->ent_ts) / 1000);
    self->ent_cfstr = 0;
    self->ent_ts    = 0;
}

/* ── CFGetTypeID (trust-boundary probe, SECD-01 pattern) ───────────────── */
pid$target::CFGetTypeID:entry
/arg0 != 0/
{
    /* Sample: 1 in ~100 to avoid storm */
    @cfget[probefunc] = count();
}

/* NOTE: optional probes like __CFAssertMismatchedTypeID and
 *       _swift_stdlib_reportFatalError live in per-process symbol tables
 *       and cause compile failures on processes without them.
 *       A companion script (xpc_trace_swift.d) adds them ONLY when targeting
 *       Swift-heavy daemons. This baseline script uses probes present
 *       in every process that links libxpc + Security. */

/* ── proc exit — crash witness ──────────────────────────────────────────── */
proc:::exit
/pid == $target/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"proc.exit\"}\n",
           walltimestamp / 1000000, pid);
    exit(0);
}

dtrace:::END
{
    printa("{\"kind\":\"cf.getTypeID.count\",\"fn\":\"%s\",\"n\":%@u}\n", @cfget);
    printf("{\"ts\":%d,\"kind\":\"dtrace.end\"}\n", walltimestamp / 1000000);
}
