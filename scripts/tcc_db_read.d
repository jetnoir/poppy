#!/usr/sbin/dtrace -s
/*
 * Poppy V5 — tcc_db_read.d
 *
 * First field deployment (2026-05-09): captures intelligenceflowd runtime
 * read pattern against the TCC database. Validates "declared (kTCCServiceAll)
 * vs observed scope" — gate #1 of the intelligenceflowd correspondence track.
 *
 * Conventions match xpc_trace.d / entitlement.d:
 *   pid-provider preferred; ts in ms (walltimestamp / 1000000); JSONL out;
 *   opaque pointers as 0x%lx; copyinstr only on confirmed C-string args.
 *
 * Usage:
 *   sudo dtrace -Z -q -s tcc_db_read.d -p $(pgrep intelligenceflowd) \
 *       -o /tmp/poppy_tcc_intelligenceflowd_$(date +%s).jsonl
 *
 * Confidence (HONEST): unconfirmed whether intelligenceflowd reads TCC.db
 * via libsqlite3 directly or via a TCC client library. Both are instrumented;
 * -Z tolerates absent probe modules at compile time.
 */

#pragma D option quiet
#pragma D option destructive
#pragma D option strsize=1024

dtrace:::BEGIN
{
    printf("{\"ts\":%d,\"kind\":\"dtrace.begin\",\"script\":\"tcc_db_read\",\"target_pid\":%d}\n",
           walltimestamp / 1000000, $target);
}

/* ── open(2) family on TCC.db ─ arg0 = const char* path (copyinstr safe) ── */
syscall::open:entry, syscall::open_nocancel:entry,
syscall::openat:entry, syscall::openat_nocancel:entry
/pid == $target/
{
    self->path = copyinstr(arg0);
    self->op_ts = timestamp;
}

syscall::open:return, syscall::open_nocancel:return,
syscall::openat:return, syscall::openat_nocancel:return
/pid == $target && self->op_ts &&
 (strstr(self->path, "TCC.db") != NULL || strstr(self->path, "com.apple.TCC") != NULL)/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"fs.open.return\",\"path\":\"%s\",\"fd\":%d,\"errno\":%d,\"us\":%d}\n",
           walltimestamp / 1000000, pid, self->path, (int)arg1, errno,
           (timestamp - self->op_ts) / 1000);
}

syscall::open:return, syscall::open_nocancel:return,
syscall::openat:return, syscall::openat_nocancel:return
/pid == $target && self->op_ts/
{ self->path = 0; self->op_ts = 0; }

/* ── libsqlite3.dylib: prepare reveals which `service` rows are queried ── */
/* sqlite3_prepare_v2(db, zSql, nByte, ppStmt, pzTail) — arg1 = const char* */
pid$target:libsqlite3.dylib:sqlite3_prepare_v2:entry,
pid$target:libsqlite3.dylib:sqlite3_prepare_v3:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"sqlite.prepare\",\"fn\":\"%s\",\"sql\":\"%s\"}\n",
           walltimestamp / 1000000, pid, probefunc, copyinstr(arg1));
}

/* sqlite3_open[_v2] arg0 = const char* filename */
pid$target:libsqlite3.dylib:sqlite3_open:entry,
pid$target:libsqlite3.dylib:sqlite3_open_v2:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"sqlite.open\",\"path\":\"%s\"}\n",
           walltimestamp / 1000000, pid, copyinstr(arg0));
}

pid$target:libsqlite3.dylib:sqlite3_step:entry
{ @steps[probefunc] = count(); }

/* ── Possible TCC client library; -Z tolerates absent module ───────────── */
pid$target:libtccd_client*::entry, pid$target:libtcc*::entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"tcc.client\",\"mod\":\"%s\",\"fn\":\"%s\"}\n",
           walltimestamp / 1000000, pid, probemod, probefunc);
}

/* ── read(2) family ─ catches reads on ALREADY-OPEN fds (long-running       ─
 *    daemons hold their backing-store fd from boot; syscall::open never      ─
 *    fires for re-reads). Capture fd; correlate fd→path offline via the      ─
 *    `lsof -p $target` sidecar that the runbook captures at script start.    ─
 *    arg0 = fd, arg2 = byte count requested.                                 ─
 */
syscall::pread:entry, syscall::pread_nocancel:entry,
syscall::read:entry,  syscall::read_nocancel:entry
/pid == $target/
{
    self->rd_fd = arg0;
    self->rd_req = arg2;
    self->rd_ts = timestamp;
}

syscall::pread:return, syscall::pread_nocancel:return,
syscall::read:return,  syscall::read_nocancel:return
/pid == $target && self->rd_ts/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"fs.read\",\"fd\":%d,\"got\":%d,\"req\":%d,\"errno\":%d,\"us\":%d}\n",
           walltimestamp / 1000000, pid, self->rd_fd, (int)arg1, self->rd_req, errno,
           (timestamp - self->rd_ts) / 1000);
    @reads_by_fd[self->rd_fd] = count();
    self->rd_fd = 0; self->rd_req = 0; self->rd_ts = 0;
}

/* ── PoirotSQLite — Apple's private SQLite wrapper. tccd + several other   ─
 *    daemons route SQL through Poirot rather than libsqlite3 directly.       ─
 *    -Z tolerates absent module on daemons that don't use it. Aggregate     ─
 *    counts only (volume could be high); printf only on a small set of      ─
 *    high-value entry points if any are stable across SDKs.                  ─
 */
pid$target:PoirotSQLite::entry
{
    @poirot[probefunc] = count();
}

/* ── Entitlement gate (CFStringRef ptr — see xpc_trace.d note) ─────────── */
pid$target::SecTaskCopyValueForEntitlement:entry
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"sec.entitlement\",\"cfstr_ptr\":\"0x%lx\"}\n",
           walltimestamp / 1000000, pid, arg1);
}

proc:::exit
/pid == $target/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"proc.exit\"}\n", walltimestamp / 1000000, pid);
    exit(0);
}

dtrace:::END
{
    printa("{\"kind\":\"sqlite.step.count\",\"fn\":\"%s\",\"n\":%@u}\n", @steps);
    printa("{\"kind\":\"reads_by_fd\",\"fd\":%d,\"n\":%@u}\n", @reads_by_fd);
    printa("{\"kind\":\"poirot.calls\",\"fn\":\"%s\",\"n\":%@u}\n", @poirot);
    printf("{\"ts\":%d,\"kind\":\"dtrace.end\"}\n", walltimestamp / 1000000);
}
