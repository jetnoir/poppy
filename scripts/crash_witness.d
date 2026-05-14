#!/usr/sbin/dtrace -s
/*
 * Poppy V5 — crash_witness.d
 *
 * System-wide crash witness. Listens for proc:::exit on processes whose
 * name contains POPPY_CRASH_PATTERN (default: "fskit"). Captures exit
 * code + last user-stack snippet via ustack(5).
 *
 * Use during fault-injection runs to catch incidental daemon crashes
 * even on processes you didn't pre-attach to.
 *
 * Usage:
 *   sudo POPPY_CRASH_PATTERN="fskit" dtrace -s crash_witness.d
 *   sudo POPPY_CRASH_PATTERN="exfat|msdos|fskit" dtrace -s crash_witness.d
 *
 * NOTE: DTrace doesn't read env vars directly. Edit the inline pattern
 *       below or pass via -D PATTERN=… on the command line:
 *   sudo dtrace -s crash_witness.d -DPATTERN='"fskit"'
 *
 * Style match: scripts/xpc_trace.d — pragma destructive, JSONL output.
 */

#pragma D option quiet
#pragma D option destructive
#pragma D option strsize=1024

#ifndef PATTERN
#define PATTERN "fskit"
#endif

dtrace:::BEGIN
{
    printf("{\"ts\":%d,\"kind\":\"dtrace.begin\",\"script\":\"crash_witness\",\"pattern\":\"%s\"}\n",
           walltimestamp / 1000000, PATTERN);
}

proc:::exit
/strstr(execname, PATTERN) != NULL/
{
    printf("{\"ts\":%d,\"pid\":%d,\"comm\":\"%s\",\"kind\":\"proc.exit\",\"code\":%d}\n",
           walltimestamp / 1000000, pid, execname, args[0]);
    ustack(5, 256);
    printf("\n");
}

dtrace:::END
{
    printf("{\"ts\":%d,\"kind\":\"dtrace.end\"}\n", walltimestamp / 1000000);
}
