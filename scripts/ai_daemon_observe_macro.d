#!/usr/sbin/dtrace -s
/*
 * Poppy V5 — ai_daemon_observe.d
 *
 * Generalized syscall-only observation harness for AI/PCC-class macOS daemons
 * (intelligenceflowd, modelmanagerd, generativeexperiencesd, intelligenceplatformd,
 * handwritingd, splunkloggingd, cloudremotediagd, …). Designed to run on a
 * SIP-on host: NO pid$1 probes are used, so it works against arbitrary
 * Apple-signed binaries where userspace pid-provider instrumentation is blocked.
 *
 * Honest reach:
 *   - Syscall + proc layer ONLY. No Swift/Obj-C/framework function visibility.
 *   - For the privacy-class question "what data does this daemon access?", the
 *     pair (file opens) + (network connects) + (read/write byte volumes) covers
 *     most of it: backing-store paths, lexicon/sqlite/plist accesses, PCC TLS
 *     egress targets, helper exec, IPC sockets. It will NOT reveal NSXPC method
 *     selectors, Sage.framework PCC routing decisions, or in-process Swift
 *     parser surface — those need pid$1 and SIP-off.
 *   - sockaddr decoding ASSUMED (Darwin layout: sa_len[1]/sa_family[1]/port[2]/
 *     addr…); first byte sa_len is not portable across kernels — VERIFY on
 *     target macOS before treating IPv4/IPv6 fields as authoritative.
 *
 * Conventions match tcc_db_read.d / xpc_trace.d:
 *   ts in ms (walltimestamp/1000000); JSONL stdout; copyinstr only on confirmed
 *   C-string args; opaque ptrs as 0x%lx; -Z tolerates absent probe modules.
 *
 * Usage:
 *   sudo dtrace -C -Z -q -s ai_daemon_observe.d \
 *       -p $(pgrep -x generativeexperiencesd) \
 *       -o /tmp/poppy_gex_$(date +%s).jsonl
 */

#pragma D option quiet
#pragma D option strsize=1024
#pragma D option specsize=4m
#pragma D option bufsize=8m

dtrace:::BEGIN
{
    printf("{\"ts\":%d,\"kind\":\"dtrace.begin\",\"script\":\"ai_daemon_observe\",\"target_pid\":%d}\n",
           walltimestamp / 1000000, $1);
}

/* ── open(2) family — capture path on entry, fd + errno on return ────────── */
syscall::open:entry, syscall::open_nocancel:entry
/pid == $1/
{
    self->o_path = copyinstr(arg0);
    self->o_ts = timestamp;
}

syscall::openat:entry, syscall::openat_nocancel:entry
/pid == $1/
{
    self->o_path = copyinstr(arg1);
    self->o_ts = timestamp;
}

syscall::open:return, syscall::open_nocancel:return,
syscall::openat:return, syscall::openat_nocancel:return
/pid == $1 && self->o_ts/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"fs.open\",\"path\":\"%s\",\"fd\":%d,\"errno\":%d,\"us\":%d}\n",
           walltimestamp / 1000000, pid, self->o_path, (int)arg1, errno,
           (timestamp - self->o_ts) / 1000);

    /* Path-prefix bucketing — coarse provenance signal. */
    @opens_by_prefix[strstr(self->o_path, "/Users/") != NULL ? "/Users/" :
                     strstr(self->o_path, "/private/var/") != NULL ? "/private/var/" :
                     strstr(self->o_path, "/private/tmp/") != NULL ? "/private/tmp/" :
                     strstr(self->o_path, "/Library/Application Support/") != NULL ? "/Library/Application Support/" :
                     strstr(self->o_path, "/System/Library/") != NULL ? "/System/Library/" :
                     strstr(self->o_path, "/Library/") != NULL ? "/Library/" :
                     strstr(self->o_path, "/var/") != NULL ? "/var/" : "other"] = count();
    self->o_path = 0; self->o_ts = 0;
}

/* ── read(2) family on already-open fds — fd→path correlated offline via
 *    lsof sidecar captured at script start (Poppy V5 convention).            */
syscall::read:entry, syscall::read_nocancel:entry,
syscall::pread:entry, syscall::pread_nocancel:entry
/pid == $1/
{
    self->r_fd = arg0;
    self->r_req = arg2;
    self->r_ts = timestamp;
}

syscall::read:return, syscall::read_nocancel:return,
syscall::pread:return, syscall::pread_nocancel:return
/pid == $1 && self->r_ts/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"fs.read\",\"fd\":%d,\"got\":%d,\"req\":%d,\"errno\":%d,\"us\":%d}\n",
           walltimestamp / 1000000, pid, self->r_fd, (int)arg1, self->r_req, errno,
           (timestamp - self->r_ts) / 1000);
    @reads_by_fd[self->r_fd] = count();
    @read_bytes_by_fd[self->r_fd] = sum((int)arg1 > 0 ? (int)arg1 : 0);
    self->r_fd = 0; self->r_req = 0; self->r_ts = 0;
}

/* ── write(2) — aggregate by fd (no content). Distinguishing file vs socket
 *    fds requires offline lsof correlation. Aggregates only.                 */
syscall::write:entry, syscall::write_nocancel:entry,
syscall::pwrite:entry, syscall::pwrite_nocancel:entry
/pid == $1/
{
    @writes_by_fd[arg0] = count();
    @write_bytes_by_fd[arg0] = sum((int)arg2);
}

/* ── connect(2) — capture sockaddr family + (best-effort) IP/port.
 *    sa_family is at offset 1 in Darwin (sa_len at offset 0). For AF_INET
 *    (2) port is offset 2 BE, addr offset 4. For AF_INET6 (30) port is
 *    offset 2 BE, addr offset 8 (skipping flowinfo). copyin guarded.         */
syscall::connect:entry, syscall::connect_nocancel:entry
/pid == $1 && arg1 != 0 && arg2 >= 2/
{
    self->sa = (uint8_t *)copyin(arg1, arg2 < 28 ? arg2 : 28);
    self->fam = self->sa[1];
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"net.connect\",\"fd\":%d,\"family\":%d,\"len\":%d}\n",
           walltimestamp / 1000000, pid, (int)arg0, self->fam, (int)arg2);
    @connect_by_family[self->fam] = count();
}

syscall::connect:entry, syscall::connect_nocancel:entry
/pid == $1 && arg1 != 0 && arg2 >= 16 && self->fam == 2/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"net.connect.inet4\",\"fd\":%d,\"port\":%d,\"a\":\"%d.%d.%d.%d\"}\n",
           walltimestamp / 1000000, pid, (int)arg0,
           (self->sa[2] << 8) | self->sa[3],
           self->sa[4], self->sa[5], self->sa[6], self->sa[7]);
}

syscall::connect:entry, syscall::connect_nocancel:entry
/pid == $1 && arg1 != 0 && arg2 >= 28 && self->fam == 30/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"net.connect.inet6\",\"fd\":%d,\"port\":%d}\n",
           walltimestamp / 1000000, pid, (int)arg0,
           (self->sa[2] << 8) | self->sa[3]);
}

syscall::connect:entry, syscall::connect_nocancel:entry
/pid == $1/
{ self->sa = 0; self->fam = 0; }

/* ── sendto / sendmsg — count + bytes per fd; no content. write_bytes_by_fd
 *    already captures most TCP egress; sendto matters for UDP/datagram.      */
syscall::sendto:entry, syscall::sendto_nocancel:entry
/pid == $1/
{
    @sendto_by_fd[arg0] = count();
    @sendto_bytes_by_fd[arg0] = sum((int)arg2);
}

/* ── exec — daemon spawning helpers (handwritingd has historically). ─────── */
proc:::exec-success
/pid == $1/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"proc.exec\",\"file\":\"%s\"}\n",
           walltimestamp / 1000000, pid, execname);
}

proc:::exit
/pid == $1/
{
    printf("{\"ts\":%d,\"pid\":%d,\"kind\":\"proc.exit\"}\n", walltimestamp / 1000000, pid);
    exit(0);
}


profile:::tick-60s
{
    exit(0);
}
dtrace:::END
{
    printa("{\"kind\":\"agg.opens_by_prefix\",\"prefix\":\"%s\",\"n\":%@u}\n", @opens_by_prefix);
    printa("{\"kind\":\"agg.reads_by_fd\",\"fd\":%d,\"n\":%@u}\n", @reads_by_fd);
    printa("{\"kind\":\"agg.read_bytes_by_fd\",\"fd\":%d,\"bytes\":%@d}\n", @read_bytes_by_fd);
    printa("{\"kind\":\"agg.writes_by_fd\",\"fd\":%d,\"n\":%@u}\n", @writes_by_fd);
    printa("{\"kind\":\"agg.write_bytes_by_fd\",\"fd\":%d,\"bytes\":%@d}\n", @write_bytes_by_fd);
    printa("{\"kind\":\"agg.connect_by_family\",\"family\":%d,\"n\":%@u}\n", @connect_by_family);
    printa("{\"kind\":\"agg.sendto_by_fd\",\"fd\":%d,\"n\":%@u}\n", @sendto_by_fd);
    printa("{\"kind\":\"agg.sendto_bytes_by_fd\",\"fd\":%d,\"bytes\":%@d}\n", @sendto_bytes_by_fd);
    printf("{\"ts\":%d,\"kind\":\"dtrace.end\"}\n", walltimestamp / 1000000);
}
