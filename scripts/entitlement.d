#!/usr/sbin/dtrace -s
/*
 * Poppy V5 — entitlement.d
 *
 * Focused trace of SecTaskCopyValueForEntitlement in a target pid.
 * Captures entitlement key + return-value pointer + duration in microseconds.
 *
 * Companion to scripts/xpc_trace.d (style match: pid-provider only,
 * one JSONL line per event, no copyinstr on CFStringRef pointers).
 *
 * Usage:
 *   sudo dtrace -s entitlement.d -p <pid>
 *
 * Note: arg1 is a CFStringRef (not a C string). This script logs the
 * pointer; resolve via Frida-side trust_boundary.js if you need the
 * literal string.
 */

#pragma D option quiet
#pragma D option destructive
#pragma D option strsize=512

dtrace:::BEGIN
{
    printf("{\"ts\":%d,\"kind\":\"dtrace.begin\",\"script\":\"entitlement\"}\n",
           walltimestamp / 1000000);
}

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
           self->ent_cfstr, arg1,
           arg1 != 0 ? 1 : 0,
           (timestamp - self->ent_ts) / 1000);
    self->ent_cfstr = 0;
    self->ent_ts    = 0;
}

proc:::exit
/pid == $target/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"proc.exit\"}\n",
           walltimestamp / 1000000, pid);
    exit(0);
}

dtrace:::END
{
    printf("{\"ts\":%d,\"kind\":\"dtrace.end\"}\n", walltimestamp / 1000000);
}
