#!/usr/bin/env python3
"""Helpers for run.sh: measurements for taodd/cephtrace PR #192.

Subcommands that touch BPF (snapshot, sample) need Linux and root.
Subcommands that talk to Ceph (flood, canary) need python3-rados.
analyze-stall and report are pure file processing.
"""
import argparse
import ctypes
import json
import multiprocessing as mp
import os
import platform
import re
import signal
import struct
import sys
import time

# ---------------------------------------------------------------- bpf syscall

BPF_MAP_GET_NEXT_KEY = 4
BPF_PROG_GET_FD_BY_ID = 13
BPF_MAP_GET_FD_BY_ID = 14
BPF_OBJ_GET_INFO_BY_FD = 15
BPF_MAP_TYPE_HASH = 1
BPF_MAP_TYPE_LRU_HASH = 9
MAP_TYPE_NAME = {BPF_MAP_TYPE_HASH: "HASH", BPF_MAP_TYPE_LRU_HASH: "LRU_HASH"}

# struct op_k { __u32 pid; __u64 owner; __u64 tid; } -> 24 bytes with padding
OPS_KEY_SIZE = 24
OPS_MAX_ENTRIES = 8192

_libc = None


def _bpf(cmd, attr):
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(None, use_errno=True)
        _libc.syscall.restype = ctypes.c_long
    nr = {"x86_64": 321, "aarch64": 280}.get(platform.machine())
    if nr is None:
        raise OSError(0, "unsupported arch " + platform.machine())
    buf = ctypes.create_string_buffer(attr, len(attr))
    ret = _libc.syscall(ctypes.c_long(nr), ctypes.c_int(cmd), buf,
                        ctypes.c_uint(len(attr)))
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret


def _fdinfo(pid):
    """Yield (kind, fields) for every bpf prog/map fd held by pid."""
    fd_dir = "/proc/%d/fd" % pid
    for fd in os.listdir(fd_dir):
        try:
            target = os.readlink(os.path.join(fd_dir, fd))
        except OSError:
            continue
        if target == "anon_inode:bpf-prog":
            kind = "prog"
        elif target == "anon_inode:bpf-map":
            kind = "map"
        else:
            continue
        fields = {}
        try:
            with open("/proc/%d/fdinfo/%s" % (pid, fd)) as f:
                for line in f:
                    k, _, v = line.partition(":")
                    fields[k.strip()] = v.strip()
        except OSError:
            continue
        yield kind, fields


def _prog_name(prog_id):
    try:
        fd = _bpf(BPF_PROG_GET_FD_BY_ID, struct.pack("<III", prog_id, 0, 0))
    except OSError:
        return "prog-%d" % prog_id
    try:
        info = ctypes.create_string_buffer(256)
        _bpf(BPF_OBJ_GET_INFO_BY_FD,
             struct.pack("<IIQ", fd, 256, ctypes.addressof(info)))
        # struct bpf_prog_info: char name[16] at offset 64
        return info.raw[64:80].split(b"\0")[0].decode() or "prog-%d" % prog_id
    except OSError:
        return "prog-%d" % prog_id
    finally:
        os.close(fd)


def prog_snapshot(pid):
    progs = {}
    for kind, f in _fdinfo(pid):
        if kind != "prog" or "prog_id" not in f:
            continue
        pid_ = int(f["prog_id"])
        if pid_ in progs:
            continue
        progs[pid_] = {
            "id": pid_,
            "name": _prog_name(pid_),
            "run_time_ns": int(f.get("run_time_ns", 0)),
            "run_cnt": int(f.get("run_cnt", 0)),
        }
    return sorted(progs.values(), key=lambda p: p["id"])


def ops_map_count(pid):
    """Count entries in the osdtrace ops map. Returns (count, type_name)."""
    for kind, f in _fdinfo(pid):
        if kind != "map":
            continue
        if (int(f.get("key_size", 0)) == OPS_KEY_SIZE
                and int(f.get("max_entries", 0)) == OPS_MAX_ENTRIES
                and int(f.get("map_type", 0)) in MAP_TYPE_NAME):
            map_id = int(f["map_id"])
            map_type = MAP_TYPE_NAME[int(f["map_type"])]
            break
    else:
        raise OSError(0, "ops map not found in pid %d" % pid)

    fd = _bpf(BPF_MAP_GET_FD_BY_ID, struct.pack("<III", map_id, 0, 0))
    try:
        cur = ctypes.create_string_buffer(OPS_KEY_SIZE)
        nxt = ctypes.create_string_buffer(OPS_KEY_SIZE)
        keys = set()
        key_ptr = 0
        # A concurrently deleted key restarts iteration from the head, so
        # dedupe and cap the walk; the count is a point-in-time approximation.
        for _ in range(OPS_MAX_ENTRIES * 4):
            try:
                _bpf(BPF_MAP_GET_NEXT_KEY,
                     struct.pack("<IIQQ", fd, 0, key_ptr, ctypes.addressof(nxt)))
            except OSError as e:
                if e.errno == 2:  # ENOENT: end of map
                    break
                raise
            keys.add(nxt.raw)
            ctypes.memmove(cur, nxt, OPS_KEY_SIZE)
            key_ptr = ctypes.addressof(cur)
        return len(keys), map_type
    finally:
        os.close(fd)


# ------------------------------------------------------------------ counters

def write_counter(path, value):
    if not path:
        return
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write("%d\n" % value)
    os.replace(tmp, path)


def read_counter(path):
    try:
        with open(path) as f:
            return int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0


# ------------------------------------------------------------ snapshot/sample

def cmd_snapshot(a):
    snap = {"time": time.time(), "progs": prog_snapshot(a.pid)}
    with open(a.out, "w") as f:
        json.dump(snap, f, indent=1)


ROW_RE = re.compile(rb"^osd \d+ pg \S+ (?:op_r|op_w|subop_w) ")


def cmd_sample(a):
    counters = []
    for spec in a.counter or []:
        name, _, path = spec.partition("=")
        counters.append((name, path))

    stop = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))

    rows = 0
    offset = 0
    partial = b""
    with open(a.csv, "w") as out:
        out.write("t,rows,ops_entries,ops_map_type%s\n"
                  % "".join("," + n for n, _ in counters))
        out.flush()
        while not stop["flag"]:
            try:
                with open(a.rows, "rb") as f:
                    f.seek(offset)
                    chunk = f.read()
                    offset += len(chunk)
                data = partial + chunk
                lines = data.split(b"\n")
                partial = lines.pop()
                rows += sum(1 for ln in lines if ROW_RE.match(ln))
            except OSError:
                pass
            try:
                entries, mtype = ops_map_count(a.pid)
            except OSError:
                entries, mtype = -1, ""
            vals = "".join(",%d" % read_counter(p) for _, p in counters)
            out.write("%.3f,%d,%d,%s%s\n" % (time.time(), rows, entries, mtype, vals))
            out.flush()
            if not os.path.exists("/proc/%d" % a.pid):
                break
            time.sleep(a.interval)


# ------------------------------------------------------------- ceph workload

def _connect(conf, name, pool):
    import rados
    cl = rados.Rados(conffile=conf, name=name)
    cl.connect()
    return rados, cl, cl.open_ioctx(pool)


def _flood_worker(conf, name, pool, prefix, idx, stop_at, done, errors):
    rados, cl, io = _connect(conf, name, pool)
    i = 0
    try:
        while time.time() < stop_at:
            try:
                io.stat("%s-%d-%d" % (prefix, idx, i))
            except rados.ObjectNotFound:
                pass
            except rados.Error:
                errors[idx] += 1
            i += 1
            done[idx] = i
    finally:
        io.close()
        cl.shutdown()


def cmd_flood(a):
    prefix = "pr192-missing-%d-%d" % (os.getpid(), int(time.time()))
    done = mp.Array("q", a.procs, lock=False)
    errors = mp.Array("q", a.procs, lock=False)
    start = time.time()
    stop_at = start + a.duration
    procs = [mp.Process(target=_flood_worker,
                        args=(a.conf, a.name, a.pool, prefix, i, stop_at, done, errors))
             for i in range(a.procs)]
    for p in procs:
        p.start()
    while any(p.is_alive() for p in procs):
        write_counter(a.counter, sum(done))
        time.sleep(0.5)
    for p in procs:
        p.join()
    total = sum(done)
    write_counter(a.counter, total)
    elapsed = time.time() - start
    print(json.dumps({"procs": a.procs, "seconds": round(elapsed, 1),
                      "missing_object_stats": total,
                      "rate_per_sec": round(total / elapsed, 1),
                      "errors": sum(errors)}))


def cmd_canary(a):
    rados, cl, io = _connect(a.conf, a.name, a.pool)
    names = ["%s-%d" % (a.prefix, i) for i in range(a.objects)]
    try:
        if a.cleanup:
            for n in names:
                try:
                    io.remove_object(n)
                except rados.ObjectNotFound:
                    pass
            return
        for n in names:
            io.write_full(n, b"pr192-canary")
        stop = {"flag": False}
        signal.signal(signal.SIGTERM, lambda *_: stop.update(flag=True))
        count = 0
        last_write = 0.0
        while not stop["flag"]:
            io.stat(names[count % len(names)])
            count += 1
            now = time.time()
            if now - last_write >= 0.2:
                write_counter(a.counter, count)
                last_write = now
            if a.interval:
                time.sleep(a.interval)
        write_counter(a.counter, count)
    finally:
        io.close()
        cl.shutdown()


# ------------------------------------------------------------------ analysis

def _load_timeline(path):
    with open(path) as f:
        header = f.readline().strip().split(",")
        rows = []
        for line in f:
            parts = line.strip().split(",")
            if len(parts) != len(header):
                continue
            rec = dict(zip(header, parts))
            for k in header:
                if k != "ops_map_type":
                    rec[k] = float(rec[k])
            rows.append(rec)
    return rows


def _load_events(path):
    ev = {}
    with open(path) as f:
        for line in f:
            name, ts = line.split()
            ev[name] = float(ts)
    return ev


def _at(samples, t, key):
    """Value of key at the last sample taken at or before t."""
    val = samples[0][key]
    for s in samples:
        if s["t"] > t:
            break
        val = s[key]
    return val


def _rate(samples, t0, t1, key):
    if t1 <= t0:
        return 0.0
    return (_at(samples, t1, key) - _at(samples, t0, key)) / (t1 - t0)


def cmd_analyze_stall(a):
    s = _load_timeline(os.path.join(a.dir, "timeline.csv"))
    ev = _load_events(os.path.join(a.dir, "events.txt"))
    b0, f0, f1, end = ev["baseline_start"], ev["flood_start"], ev["flood_stop"], ev["end"]

    stall = None
    last_change_t = f0
    last_rows = _at(s, f0, "rows")
    for rec in s:
        if rec["t"] < f0:
            continue
        if rec["rows"] != last_rows:
            last_rows = rec["rows"]
            last_change_t = rec["t"]
            continue
        if rec["t"] - last_change_t >= a.window:
            canary_moved = _at(s, rec["t"], "canary") > _at(s, last_change_t, "canary")
            if canary_moved:
                stall = {
                    "seconds_after_flood_start": round(last_change_t - f0, 1),
                    "missing_object_stats_sent": int(_at(s, last_change_t, "flood")),
                    "ops_entries_at_stall": int(_at(s, last_change_t, "ops_entries")),
                }
                break

    flood = {}
    try:
        with open(os.path.join(a.dir, "flood.log")) as f:
            flood = json.loads(f.read().strip().splitlines()[-1])
    except (OSError, ValueError, IndexError):
        pass

    out = {
        "ops_map_type": next((r["ops_map_type"] for r in s if r["ops_map_type"]), ""),
        "rows_per_sec_baseline": round(_rate(s, b0, f0, "rows"), 1),
        "rows_per_sec_flood": round(_rate(s, f0, f1, "rows"), 1),
        "rows_per_sec_after_flood": round(_rate(s, f1, end, "rows"), 1),
        "canary_stats_per_sec": round(_rate(s, b0, end, "canary"), 1),
        "ops_entries_max": int(max(r["ops_entries"] for r in s)),
        "ops_entries_end": int(s[-1]["ops_entries"]),
        "stall": stall,
        "flood": flood,
    }
    json.dump(out, sys.stdout, indent=1)
    print()


FRIENDLY = [
    ("uprobe_enqueue_", "uprobe_enqueue_op"),
    ("uprobe_dequeue_", "uprobe_dequeue_op"),
    ("uprobe_execute_", "uprobe_execute_ctx"),
    ("uprobe_log_op_s", "uprobe_log_op_stats"),
    ("uprobe_repop_co", "uprobe_repop_commit"),
    ("uprobe_log_subo", "uprobe_log_subop_stats"),
    ("uprobe_mark_fla", "uprobe_mark_flag_point*"),
]


def _group_delta(before, after):
    b = {p["id"]: p for p in before["progs"]}
    groups = {}
    for p in after["progs"]:
        if p["id"] not in b:
            continue
        key = p["name"][:15]
        g = groups.setdefault(key, [0, 0])
        g[0] += p["run_time_ns"] - b[p["id"]]["run_time_ns"]
        g[1] += p["run_cnt"] - b[p["id"]]["run_cnt"]
    return groups


def _perf_variant(perf_dir, variant):
    totals = {}
    iops = []
    rounds = 0
    for d in sorted(os.listdir(perf_dir)):
        if not d.startswith(variant + "-r"):
            continue
        path = os.path.join(perf_dir, d)
        try:
            with open(os.path.join(path, "before.json")) as f:
                before = json.load(f)
            with open(os.path.join(path, "after.json")) as f:
                after = json.load(f)
        except OSError:
            continue
        rounds += 1
        for key, (rt, cnt) in _group_delta(before, after).items():
            t = totals.setdefault(key, [0, 0])
            t[0] += rt
            t[1] += cnt
        m = _grep_iops(os.path.join(path, "bench.log"))
        if m is not None:
            iops.append(m)
    return totals, iops, rounds


def _grep_iops(path):
    try:
        with open(path) as f:
            m = re.search(r"Average IOPS:\s+(\d+)", f.read())
        return int(m.group(1)) if m else None
    except OSError:
        return None


def _read_kv(path):
    kv = {}
    try:
        with open(path) as f:
            for line in f:
                k, _, v = line.rstrip("\n").partition("=")
                if k:
                    kv[k] = v
    except OSError:
        pass
    return kv


def _fmt(v):
    return "–" if v is None else str(v)


def cmd_report(a):
    r = a.results
    env = _read_kv(os.path.join(r, "env.txt"))
    commits = _read_kv(os.path.join(r, "commits.txt"))
    print("<!-- generated by bench-pr192/run.sh; review before pasting -->\n")
    print("Environment: %s-OSD cluster (%s OSD(s) traced on this host, %s), Ceph %s, "
          "%s (%s CPUs, possible %s), kernel %s, %s. `main` = `%s`, this PR = `%s`.\n"
          % (env.get("osds_total", "?"), env.get("osds_local", "?"),
             env.get("deploy", "?"), env.get("ceph_osd_version", "?"),
             env.get("cpu_model", "?"), env.get("nproc", "?"),
             env.get("cpu_possible", "?"), env.get("kernel", "?"),
             env.get("os", "?"), commits.get("main", "?"), commits.get("pr", "?")))

    stall = {}
    for v in ("main", "pr"):
        try:
            with open(os.path.join(r, "stall-" + v, "summary.json")) as f:
                stall[v] = json.load(f)
        except (OSError, ValueError):
            stall[v] = None
    if stall["main"] or stall["pr"]:
        m, p = stall["main"] or {}, stall["pr"] or {}
        fl = (m.get("flood") or p.get("flood") or {})
        print("**Reproducing the stall (full mode)**\n")
        print("Workload: a canary process `stat`s %s existing objects while %s processes "
              "`stat` missing objects (≈%s ops/s) in a dedicated test pool.\n"
              % (env.get("canary_objects", "?"), fl.get("procs", "?"),
                 fl.get("rate_per_sec", "?")))
        print("| | main | this PR |")
        print("| :--- | ---: | ---: |")

        def row(label, key):
            print("| %s | %s | %s |" % (label, _fmt(m.get(key)), _fmt(p.get(key))))

        row("`ops` map type", "ops_map_type")
        row("rows/s before flood", "rows_per_sec_baseline")
        row("rows/s during flood", "rows_per_sec_flood")
        row("rows/s after flood stopped", "rows_per_sec_after_flood")
        row("`ops` entries, max", "ops_entries_max")
        row("`ops` entries, end", "ops_entries_end")

        def stall_txt(x):
            st = x.get("stall")
            if not x:
                return "–"
            if not st:
                return "none"
            return "after %ss (%s missing-object stats, %s entries)" % (
                st["seconds_after_flood_start"], st["missing_object_stats_sent"],
                st["ops_entries_at_stall"])

        print("| output stalled | %s | %s |\n" % (stall_txt(m), stall_txt(p)))

    perf_dir = os.path.join(r, "perf")
    if os.path.isdir(perf_dir):
        main_t, main_iops, main_rounds = _perf_variant(perf_dir, "main")
        pr_t, pr_iops, pr_rounds = _perf_variant(perf_dir, "pr")
        print("**Performance**\n")
        print("`rados bench %s write -b %s -t %s`, full mode, `bpf_stats` run_time/run_cnt "
              "summed over %s round(s) per variant (alternating):\n"
              % (env.get("bench_secs", "?"), env.get("bench_bs", "?"),
                 env.get("bench_threads", "?"), min(main_rounds, pr_rounds)))
        print("| Program | main ns/hit | this PR ns/hit | Δ | hits (main / PR) |")
        print("| :--- | ---: | ---: | ---: | ---: |")

        def nshit(t, key):
            rt, cnt = t.get(key, (0, 0))
            return (rt / cnt) if cnt else None

        for key, label in FRIENDLY:
            a_, b_ = nshit(main_t, key), nshit(pr_t, key)
            if a_ is None and b_ is None:
                continue
            delta = ("%+.1f%%" % ((b_ - a_) / a_ * 100)) if a_ and b_ else "–"
            print("| `%s` | %s | %s | %s | %s / %s |" % (
                label, _fmt(a_ and round(a_)), _fmt(b_ and round(b_)), delta,
                main_t.get(key, (0, 0))[1], pr_t.get(key, (0, 0))[1]))

        def per_op(t):
            enq = t.get("uprobe_enqueue_", (0, 0))[1]
            return (sum(v[0] for v in t.values()) / enq) if enq else None

        a_, b_ = per_op(main_t), per_op(pr_t)
        delta = ("%+.1f%%" % ((b_ - a_) / a_ * 100)) if a_ and b_ else "–"
        print("| all osdtrace programs, per enqueued op | %s | %s | %s | |\n"
              % (_fmt(a_ and round(a_)), _fmt(b_ and round(b_)), delta))

        base = _grep_iops(os.path.join(perf_dir, "notracer", "bench.log"))

        def avg(xs):
            return round(sum(xs) / len(xs)) if xs else None

        print("Client IOPS: no tracer %s / main %s / this PR %s\n"
              % (_fmt(base), _fmt(avg(main_iops)), _fmt(avg(pr_iops))))


# ---------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("snapshot")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_snapshot)

    p = sub.add_parser("sample")
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--rows", required=True)
    p.add_argument("--csv", required=True)
    p.add_argument("--counter", action="append", help="name=path")
    p.add_argument("--interval", type=float, default=1.0)
    p.set_defaults(fn=cmd_sample)

    for name, fn in (("flood", cmd_flood), ("canary", cmd_canary)):
        p = sub.add_parser(name)
        p.add_argument("--conf", required=True)
        p.add_argument("--name", required=True)
        p.add_argument("--pool", required=True)
        p.add_argument("--counter")
        p.set_defaults(fn=fn)
        if name == "flood":
            p.add_argument("--procs", type=int, default=16)
            p.add_argument("--duration", type=float, required=True)
        else:
            p.add_argument("--prefix", default="pr192-canary")
            p.add_argument("--objects", type=int, default=64)
            p.add_argument("--interval", type=float, default=0.0)
            p.add_argument("--cleanup", action="store_true")

    p = sub.add_parser("analyze-stall")
    p.add_argument("--dir", required=True)
    p.add_argument("--window", type=float, default=20)
    p.set_defaults(fn=cmd_analyze_stall)

    p = sub.add_parser("report")
    p.add_argument("--results", required=True)
    p.set_defaults(fn=cmd_report)

    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
