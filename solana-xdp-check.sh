#!/usr/bin/env bash
# ONE self-contained script; ONE new private text report; observations only.
# Linux + Bash + Python 3.8 standard library. No downloads or package installs.
# Run: bash solana-xdp-check.sh --interface bond0
# Optional: --pid 12345 --service validator.service --seconds 60
#           --log-file /absolute/validator.log --output ./xdp-check.txt
# Default report location: the current directory you run this command from.
# Help/tests: --help / --self-test (embedded; no other files required).
# Default: 60 seconds of measurement + at most 120 seconds for other work.
# Countdown is remaining cooperative runtime budget; blocked kernel reads can
# overrun it. Normal checks often finish earlier. Nothing is tuned or restarted.
# Checks compare the requested XDP capability/configuration profile.
# Requirements vary with the installed implementation; its build is unverified.
# No attached program/capability alone proves active RX or zero-copy traffic.
set -eu
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'ERROR: Python 3.8+ is required. Nothing was installed or changed.' >&2
  exit 3
fi
exec python3 -I -B -u - "$@" <<'PY_SOLANA_XDP_SINGLE'
"""One-file, one-report, read-only Linux XDP check. Python 3.8+."""
from __future__ import annotations

import argparse

import collections

import datetime as dt

import errno

import json

import math

import os

from pathlib import Path

import platform

import re

import selectors

import shutil

import signal

import stat

import struct

import subprocess

import sys

import tempfile

import time

import unittest

VERSION = "3.0"

CAP_NAMES = ("chown dac_override dac_read_search fowner fsetid kill setgid setuid "
             "setpcap linux_immutable net_bind_service net_broadcast net_admin "
             "net_raw ipc_lock ipc_owner sys_module sys_rawio sys_chroot sys_ptrace "
             "sys_pacct sys_admin sys_boot sys_nice sys_resource sys_time sys_tty_config "
             "mknod lease audit_write audit_control setfcap mac_override mac_admin "
             "syslog wake_alarm block_suspend audit_read perfmon bpf checkpoint_restore").split()

BASE_CAPS = {"cap_net_admin", "cap_net_raw", "cap_bpf", "cap_perfmon"}

VALUE_FLAGS = {"--xdp-interface", "--xdp-cpu-cores", "--xdp-queue-base",
               "--rpc-niceness-adjustment", "--snapshot-packager-niceness-adjustment",
               "--poh-pinned-cpu-core", "--unified-scheduler-handler-threads",
               "--replay-forks-threads", "--replay-transactions-threads",
               "--log", "--ledger", "--accounts"}

BOOL_FLAGS = {"--no-xdp", "--xdp-zero-copy", "--xdp-chain-loading", "--no-voting"}

HIDDEN_FLAGS = {"--log", "--ledger", "--accounts"}

NIC_KEYS = "rx_packets tx_packets rx_bytes tx_bytes rx_dropped tx_dropped rx_errors tx_errors rx_missed_errors rx_crc_errors rx_fifo_errors rx_over_errors tx_carrier_errors".split()

ISSUE_PATTERN = re.compile(r"drop|miss|err|discard|no.?buf|overflow|timeout|fail", re.I)

DRIVER_PATTERN = re.compile(r"drop|miss|err|discard|no.?buf|overflow|timeout|fail|xdp|xsk", re.I)

XDP_PATTERN = re.compile(r"xdp|xsk|ntuple|steering|cap_bpf|cap_perfmon|cap_sys_nice", re.I)

REPLAY_PATTERN = re.compile(r"replay-slot-stats|replay.*(slow|stall|error)|clean_accounts|accounts.*(stall|slow)|shred.*(drop|lost|missing)|repair.*(fail|slow)|new root|bank frozen", re.I)

TRUSTED_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"

def clean(text):
    """Conservative display redaction; recursively apply to structured output too.

    A secret marker suppresses the entire line, including spaced bearer values.
    This is not anonymization: IP addresses, public IDs and topology remain.
    """
    text = str(text)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = re.sub(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s\"'<>]+", "[URL_REDACTED]", text)
    if re.search(r"(?i)\b(?:api[_-]?key|access[_-]?token|password|private[_-]?key|secret|authorization|bearer|seed[_ -]?phrase|mnemonic)\b|-----BEGIN .*PRIVATE", text):
        return "[SENSITIVE_TEXT_REDACTED]"
    text = re.sub(r"\[\s*\d{1,3}(?:\s*,\s*\d{1,3}){31,}\s*\]", "[BYTE_ARRAY_REDACTED]", text)
    return "".join(c if c in "\n\t" or 32 <= ord(c) < 127 else "?" for c in text)

def parse_flags(argv):
    """Whitelist flags. Never print the complete command line or keypair paths."""
    result = {}
    i = 1
    while i < len(argv):
        arg = argv[i]
        key, sep, val = arg.partition("=")
        if key in BOOL_FLAGS:
            result[key] = val.lower() not in ("false", "0", "no") if sep else True
        elif key in VALUE_FLAGS:
            if not sep:
                val = argv[i + 1] if i + 1 < len(argv) and not argv[i + 1].startswith("--") else None
                if val is not None:
                    i += 1
            result[key] = val
        i += 1
    return result

def cpulist(value):
    if value is None:
        return None
    out = set()
    try:
        for part in value.strip().split(","):
            if not part:
                continue
            lo, dash, hi = part.partition("-")
            a, b = int(lo), int(hi) if dash else int(lo)
            if a < 0 or b < a or b > 65535:
                return None
            out.update(range(a, b + 1))
        return out
    except ValueError:
        return None

def mask_cpus(value):
    try:
        value = value.strip()
        if len(value) > 18432 or not re.fullmatch(r"[0-9a-fA-F]{1,8}(?:,[0-9a-fA-F]{8})*|[0-9a-fA-F]{1,16384}", value):
            return None
        bits = int(value.replace(",", ""), 16)
        return {i for i in range(bits.bit_length()) if bits & (1 << i)}
    except (AttributeError, ValueError):
        return None

def show_cpus(values):
    if values is None:
        return "UNKNOWN"
    if not values:
        return "none"
    spans = []
    for _, group in __import__("itertools").groupby(enumerate(sorted(values)), lambda z: z[1] - z[0]):
        nums = [x[1] for x in group]
        spans.append(str(nums[0]) if len(nums) == 1 else "%d-%d" % (nums[0], nums[-1]))
    return ",".join(spans)

def cap_names(mask):
    if not isinstance(mask, int) or mask < 0 or mask.bit_length() > 64:
        raise ValueError("invalid capability mask")
    return {"cap_" + (CAP_NAMES[i] if i < len(CAP_NAMES) else "unknown_%d" % i)
            for i in range(mask.bit_length()) if mask & (1 << i)}

def decode_file_caps(raw):
    """Decode Linux VFS capability revisions 1/2/3, including namespaced root ID."""
    if len(raw) < 12:
        raise ValueError("short capability xattr")
    magic = struct.unpack_from("<I", raw)[0]
    rev = magic >> 24
    expected = {1: 12, 2: 20, 3: 24}.get(rev)
    if expected is None or len(raw) != expected:
        raise ValueError("unsupported capability xattr format")
    permitted, inheritable = struct.unpack_from("<II", raw, 4)
    if rev >= 2:
        highp, highi = struct.unpack_from("<II", raw, 12)
        permitted |= highp << 32
        inheritable |= highi << 32
    return {"permitted": sorted(cap_names(permitted)), "inheritable": sorted(cap_names(inheritable)),
            "effective_bit": bool(magic & 1), "rootid": struct.unpack_from("<I", raw, 20)[0] if rev == 3 else None}

def proc_stat(text):
    """/proc PID stat comm can contain spaces and parentheses: split at last ')' ."""
    if not text or ")" not in text:
        return None
    try:
        a = text[text.rfind(")") + 2:].split()
        return {"name": text[text.find("(") + 1:text.rfind(")")], "ticks": int(a[11]) + int(a[12]),
                "start": int(a[19]), "cpu": int(a[36]), "state": a[0]}
    except (ValueError, IndexError):
        return None

def delta_value(before, after):
    if before is None or after is None:
        return None, "unavailable"
    if after < before:
        return None, "reset_or_wrap"
    return after - before, "ok"

def parse_driver(text):
    out = {}
    for line in (text or "").splitlines():
        m = re.match(r"\s*([^:]+):\s*([0-9]+)\s*$", line)
        if m and DRIVER_PATTERN.search(m[1]):
            out[m[1].strip()] = int(m[2])
    return out

def parse_cpu(text):
    result = {}
    for line in (text or "").splitlines():
        p = line.split()
        if p and re.fullmatch(r"cpu\d*", p[0]) and len(p) >= 9:
            try:
                # guest time already appears in user/nice. Do not count it twice.
                result[p[0]] = [int(x) for x in p[1:9]]
            except ValueError:
                pass
    return result

def cpu_percent(before, after):
    if before is None or after is None or len(before) != 8 or len(after) != 8:
        return None
    d = [b - a for a, b in zip(before, after)]
    # Linux documents that iowait can decrease. Invalidate, never clamp to fake data.
    if min(d) < 0 or sum(d) <= 0:
        return None
    total = sum(d)
    return {"work": 100 * sum(d[i] for i in (0, 1, 2, 5, 6)) / total,
            "iowait": 100 * d[4] / total, "irq": 100 * d[5] / total,
            "softirq": 100 * d[6] / total, "steal": 100 * d[7] / total}

def parse_softnet(text):
    out = {}
    for row, line in enumerate((text or "").splitlines()):
        try:
            p = [int(x, 16) for x in line.split()]
            if len(p) < 3:
                continue
            # Column 13 is the CPU ID on modern kernels; offline CPUs are omitted.
            label = "cpu%d" % p[12] if len(p) >= 13 else "row%d" % row
            out[label] = {"processed": p[0], "drops": p[1], "squeezes": p[2]}
        except ValueError:
            continue
    return out

def parse_udp(text, ipv6=False):
    if ipv6:
        out = {}
        for line in (text or "").splitlines():
            p = line.split()
            if len(p) == 2 and p[0].startswith("Udp6") and p[1].isdigit():
                out[p[0][4:]] = int(p[1])
        return out
    header = None
    for line in (text or "").splitlines():
        p = line.split()
        if not p or p[0] != "Udp:":
            continue
        if header is None:
            header = p[1:]
        else:
            return {k: int(v) for k, v in zip(header, p[1:]) if v.isdigit()}
    return {}

def parse_irqs(text):
    lines = (text or "").splitlines()
    if not lines:
        return {}, []
    cpus = re.findall(r"CPU(\d+)", lines[0])
    result = {}
    for line in lines[1:]:
        left, sep, right = line.partition(":")
        if not sep or not left.strip().isdigit():
            continue
        p = right.split()
        try:
            counts = [int(x) for x in p[:len(cpus)]]
            if len(counts) == len(cpus):
                result[left.strip()] = {"counts": dict(zip(cpus, counts)), "label": " ".join(p[len(cpus):])}
        except ValueError:
            continue
    return result, cpus

def parse_channels(text):
    out = {"maximum": {}, "current": {}}
    group = None
    for line in (text or "").splitlines():
        if "Pre-set maximums" in line:
            group = "maximum"
        elif "Current hardware settings" in line:
            group = "current"
        elif group:
            m = re.match(r"\s*(RX|TX|Other|Combined):\s*(\d+)", line)
            if m:
                out[group][m[1]] = int(m[2])
    return out

def required_caps(flags):
    """Return explicit lower bound ONLY; omitted defaults are unresolved.

    Caller must gate on independently identified reference XDP profile source and must never
    call this set a complete fresh-start proof. Niceness defaults need a profile.
    """
    needed = set(BASE_CAPS)
    if flags.get("--xdp-chain-loading"):
        needed.add("cap_sys_admin")
    for f in ("--rpc-niceness-adjustment", "--snapshot-packager-niceness-adjustment"):
        try:
            if int(flags.get(f, 0)) != 0:
                needed.add("cap_sys_nice")
        except (ValueError, TypeError):
            raise ValueError("invalid niceness flag")
    return needed

import threading
import uuid
import io
import contextlib
sys.dont_write_bytecode = True
def trusted_code(path):
    """Privileged Python must not import code from a user-writable directory."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        for p in (path,) + tuple(path.parents):
            s = p.stat()
            if s.st_uid != 0 or s.st_mode & 0o022:
                raise RuntimeError("Root execution requires root-owned code/parents without group/world write")

VERSION = "4.0-simple"

SCHEMA = "solana-validator-audit/3"

TRUSTED_DIRS = ("/usr/sbin", "/usr/bin", "/sbin", "/bin")

TOOLS = {"ip", "ethtool", "bpftool", "ss", "systemctl", "findmnt",
         "lsblk", "df", "lscpu", "timedatectl"}

AREAS = {"A": "Improved XDP and bonded-interface support",
         "B": "XDP capabilities and startup permissions",
         "C": "Other Alpenglow and validator/server improvements"}

LEVELS = {"OK", "INFO", "WARN", "UNKNOWN", "NOT_APPLICABLE", "ERROR"}

MAX_FILE = 2 * 1024 * 1024

MAX_TASKS = 512

MAX_DEVICES = 16

MAX_INVENTORY = 4096

MAX_SERIES = 12000

SAFE_IFACE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.:@-]{0,14}\Z")

SAFE_SERVICE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.@:-]{0,199}\.service\Z")

SENSITIVE_NAME = re.compile(r"(?i)(keypair|private|secret|wallet|credential|identity|authorized.voter|seed|token)")

def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")

def sanitized(value):
    """Apply the same redaction at every persistence boundary, including keys."""
    if isinstance(value, str):
        return clean(value)
    if isinstance(value, dict):
        result = {}
        for k, v in value.items():
            key = clean(str(k))
            sensitive_key = key == "[SENSITIVE_TEXT_REDACTED]"
            # Do not let redacted key collisions silently replace other records.
            if key in result:
                key += "#%d" % len(result)
            result[key] = "[REDACTED]" if sensitive_key else sanitized(v)
        return result
    if isinstance(value, (tuple, list, set)):
        return [sanitized(x) for x in value]
    if isinstance(value, float) and not math.isfinite(value):
        return None
    return value

def valid_iface(name):
    return isinstance(name, str) and bool(SAFE_IFACE.fullmatch(name)) and name not in (".", "..")

def safe_read(path, limit=MAX_FILE, nofollow=False):
    """Bounded virtual-file reads. Return (text, explicit reason), never zero.

    Sysfs class symlinks are intentional; caller constructs these from validated
    identifiers. External files use nofollow=True and checked path components.
    """
    fd = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        if nofollow:
            flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None, "not_regular"
        chunks, left = [], limit + 1
        while left:
            b = os.read(fd, min(left, 65536))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        raw = b"".join(chunks)
        if len(raw) > limit:
            return None, "read_limit"
        return raw.decode("utf-8", "replace"), "ok"
    except OSError as e:
        return None, errno.errorcode.get(e.errno, "read_error")
    finally:
        if fd is not None:
            os.close(fd)

def external_path(path, log=False):
    p = Path(path)
    if not p.is_absolute() or ".." in p.parts:
        raise ValueError("input path must be absolute without parent traversal")
    for component in (p,) + tuple(p.parents):
        if component.is_symlink():
            raise ValueError("external input paths must not contain symlinks")
    if not p.is_file():
        raise ValueError("input must be a regular existing file")
    if log and (SENSITIVE_NAME.search(str(p)) or p.suffix.lower() not in (".log", ".txt")):
        raise ValueError("only explicitly supplied .log/.txt operational logs without sensitive path names")
    return p

def open_external(path):
    """Open each path component relative to a held directory, without symlinks.

    The Linux audit uses this instead of trusting a check-then-open path walk.
    Windows fallback exists only for portable parser/mock tests, never live audit.
    """
    p = Path(path)
    if not p.is_absolute() or ".." in p.parts:
        raise ValueError("external path must be absolute")
    if not sys.platform.startswith("linux"):
        fd = os.open(str(external_path(p)), os.O_RDONLY | getattr(os, "O_BINARY", 0))
    else:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            for component in p.parts[1:-1]:
                next_dir = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory)
                os.close(directory)
                directory = next_dir
            fd = os.open(p.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=directory)
        finally:
            os.close(directory)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ValueError("external input is not regular")
    return fd

def listed(path, limit):
    """Bound enumeration before materializing lists; preserve truncation reason."""
    try:
        values = []
        with os.scandir(path) as it:
            for entry in it:
                if len(values) >= limit:
                    return values, "entry_limit"
                values.append(entry.name)
        return sorted(values), "ok"
    except OSError as e:
        return [], errno.errorcode.get(e.errno, "list_error")

def integers(text, separator=":"):
    out = {}
    for line in (text or "").splitlines():
        p = line.replace(separator, " ", 1).split()
        if len(p) >= 2 and re.fullmatch(r"[0-9]+", p[1]):
            out[p[0]] = int(p[1])
    return out

def int_read(path):
    text, reason = safe_read(path, 4096)
    try:
        return int(text.strip()), reason
    except (TypeError, ValueError):
        return None, reason if reason != "ok" else "malformed_integer"

def identity(pid):
    """A PID alone is not a process identity. Never reads the environment."""
    base = "/proc/%d" % pid
    parsed = proc_stat(safe_read(base + "/stat", 65536)[0])
    if not parsed:
        return None
    try:
        s = os.stat(base + "/exe")
        return {"pid": pid, "start_ticks": parsed["start"], "exe_dev": s.st_dev,
                "exe_inode": s.st_ino, "exe_size": s.st_size, "exe_mtime_ns": s.st_mtime_ns,
                "exe_path": os.readlink(base + "/exe"),
                "netns": os.readlink(base + "/ns/net"), "userns": os.readlink(base + "/ns/user"),
                "mntns": os.readlink(base + "/ns/mnt"),
                "boot_id": (safe_read("/proc/sys/kernel/random/boot_id", 128)[0] or "").strip()}
    except OSError:
        return None

def route_choice(routes4, routes6, rules4, rules6):
    """No lowest-metric guess across policy tables, IPv4/IPv6 or multipath."""
    for rules in (rules4, rules6):
        if not isinstance(rules, list) or not rules:
            return None, "rules_unavailable"
        for r in rules:
            if not isinstance(r, dict) or str(r.get("table")) not in ("local", "main", "default", "253", "254", "255"):
                return None, "policy_routing"
            if any(k in r for k in ("fwmark", "iif", "oif", "uidrange", "ipproto", "sport", "dport")) or r.get("src", "all") not in ("all", "0.0.0.0/0", "::/0") or r.get("dst", "all") not in ("all", "0.0.0.0/0", "::/0"):
                return None, "policy_routing"
    if not isinstance(routes4, list) or not isinstance(routes6, list):
        return None, "routes_unavailable"
    routes = routes4 + routes6
    if not routes:
        return None, "no_default_route"
    names = set()
    for r in routes:
        if not isinstance(r, dict) or any(k in r for k in ("nexthops", "nhid", "multipath")) or not valid_iface(r.get("dev")):
            return None, "multipath_or_malformed_route"
        names.add(r["dev"])
    return (next(iter(names)), "unique_default_device") if len(names) == 1 else (None, "multiple_default_devices")

def ntuple_state(text):
    m = re.search(r"^\s*rx-ntuple-filter:\s+(on|off)(\s+\[fixed\])?", text or "", re.M)
    return (m[1] + ("_fixed" if m[2] else "")) if m else "unavailable"

def queue_overlap(a, b):
    """Half-open ranges. Width missing is UNKNOWN, never disjoint."""
    if any(type(x) is not int or x < 0 for x in a + b) or a[1] == 0 or b[1] == 0:
        return None
    return max(a[0], b[0]) < min(a[0] + a[1], b[0] + b[1])

class BudgetExceeded(RuntimeError):
    pass

class Runner:
    """Only our new session is killed, while its leader remains unreaped.

    Keeping the leader (including its zombie) until killpg prevents PID/PGID reuse
    between completion and cleanup. No signal is sent to a validator PID.
    """
    def __init__(self, deadline, timeout=4, output_limit=32768):
        self.deadline, self.timeout, self.output_limit = deadline, timeout, output_limit
        self.calls = 0

    def run(self, argv):
        start, wall = time.monotonic(), utc()
        result = {"argv": argv, "source": "read-only system utility", "start_utc": wall,
                  "mono_start_s": start, "returncode": None, "status": "unavailable", "output": ""}
        if not argv or argv[0] not in TOOLS:
            raise ValueError("command not in read-only inventory")
        if hasattr(signal, "SIGCHLD") and signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
            raise RuntimeError("child cleanup requires default SIGCHLD disposition")
        if self.calls >= 512 or start >= self.deadline:
            result["reason"] = "command_or_runtime_budget"
        else:
            self.calls += 1
            executable = None
            for d in TRUSTED_DIRS:
                p = Path(d) / argv[0]
                if p.is_file():
                    resolved = p.resolve()
                    try:
                        trusted_code(resolved)
                        executable = str(resolved)
                        break
                    except (RuntimeError, OSError):
                        continue
            if not executable:
                result["reason"] = "missing_or_untrusted_tool"
            else:
                p, sel, raw = None, None, bytearray()
                try:
                    p = subprocess.Popen([executable] + argv[1:], stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True,
                        close_fds=True, env={"PATH": ":".join(TRUSTED_DIRS), "LC_ALL": "C", "LANG": "C",
                                             "SYSTEMD_PAGER": "cat", "SYSTEMD_COLORS": "0"})
                    sel = selectors.DefaultSelector()
                    sel.register(p.stdout, selectors.EVENT_READ)
                    end = min(start + self.timeout, self.deadline)
                    eof = False
                    while True:
                        now = time.monotonic()
                        if now >= end:
                            result.update(status="timeout", reason="command_deadline")
                            break
                        exited = os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                        if eof and exited is not None:
                            result.update(status="ok", reason="completed")
                            break
                        for key, _ in sel.select(min(0.1, end - now)):
                            chunk = os.read(key.fileobj.fileno(), min(8192, self.output_limit + 1 - len(raw)))
                            if not chunk:
                                eof = True
                                sel.unregister(key.fileobj)
                            else:
                                raw.extend(chunk)
                        if len(raw) > self.output_limit:
                            result.update(status="truncated", reason="command_output_limit")
                            break
                except OSError as e:
                    result.update(status="unavailable", reason=errno.errorcode.get(e.errno, "spawn_error"))
                finally:
                    if p is not None:
                        # DO NOT call poll()/wait() before killpg: they reap the
                        # leader and remove the reservation against PID reuse.
                        try:
                            os.killpg(p.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        try:
                            result["returncode"] = p.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            result.update(status="unavailable", reason="unreaped_child")
                        if p.stdout:
                            p.stdout.close()
                    if sel:
                        sel.close()
                    result["output"] = clean(raw[:self.output_limit].decode("utf-8", "replace"))
                if result["status"] == "ok" and result["returncode"] != 0:
                    result.update(status="unsupported_or_denied", reason="nonzero_exit")
        result.update(end_utc=utc(), mono_end_s=time.monotonic())
        return result

class CoreAudit:
    def __init__(self, args, report, runner=None):
        self.args, self.report = args, report
        self.started = time.monotonic()
        self.deadline = self.started + args.max_runtime
        self.runner = runner or Runner(self.deadline, args.command_timeout)
        self.data = {"schema": SCHEMA, "tool_version": VERSION, "started_utc": utc(),
            "execution_status": "running", "health_verdict": "NOT_DETERMINED",
            "areas": AREAS, "selection": {}, "inventory": [], "findings": [],
            "series": {}, "coverage": [], "overhead": {}, "imports": []}
        self.process = None
        self.flags = {}
        self.devices = []
        self.nic_irqs = set()
        self.netns_ok = False
        self.sample_count = 0
        self.collection_s = 0.0
        self.inventory_count = 0
        self.finding_keys = set()
        self.cpu_seconds_start = time.process_time()

    def budget(self):
        if time.monotonic() >= self.deadline:
            raise BudgetExceeded("overall runtime deadline")

    def finding(self, area, code, level, scope, message, next_step, confidence="limited"):
        assert area in AREAS and level in LEVELS
        key = (area, code, scope)
        if key in self.finding_keys:
            return
        self.finding_keys.add(key)
        row = {"area": area, "code": code, "level": level, "scope": scope,
               "confidence": confidence, "message": message, "next_step": next_step}
        self.data["findings"].append(row)
        self.report.record("finding", row)

    def observation(self, area, id_, scope, value, source, kind="configuration", unit="text", reason="ok", start=None):
        self.budget()
        if self.inventory_count >= MAX_INVENTORY:
            raise BudgetExceeded("inventory record limit")
        self.inventory_count += 1
        row = {"area": area, "id": id_, "scope": scope, "kind": kind, "unit": unit,
               "source": source, "status": "observed" if reason == "ok" else "unavailable",
               "reason": reason, "start_utc": start[0] if start else utc(), "end_utc": utc(),
               "mono_start_s": start[1] if start else time.monotonic(), "mono_end_s": time.monotonic(), "value": value}
        self.report.record("observation", row)
        # Compact inventory in checkpoint; full text always in streaming record.
        compact = dict(row)
        if isinstance(value, str) and len(value) > 2048:
            compact["value"] = value[:2048]
            compact["summary_truncated"] = True
        self.data["inventory"].append(compact)
        return row

    def read(self, area, id_, scope, path, kind="configuration", unit="text", limit=65536):
        began = utc(), time.monotonic()
        value, reason = safe_read(path, limit)
        return self.observation(area, id_, scope, value, path, kind, unit, reason, began)

    def command(self, area, id_, scope, argv):
        self.budget()
        r = self.runner.run(argv)
        r.update(area=area, id=id_, scope=scope)
        self.report.record("command", r)
        self.observation(area, id_, scope, r["output"], "command:" + " ".join(argv),
                         "observation", "text", "ok" if r["status"] == "ok" else r["status"] + ":" + r["reason"],
                         (r["start_utc"], r["mono_start_s"]))
        return r

    def json_command(self, area, id_, argv):
        r = self.command(area, id_, "audit network namespace", argv)
        if r["status"] != "ok":
            return None
        try:
            return json.loads(r["output"])
        except (ValueError, RecursionError):
            return None

    def select(self):
        requested = self.args.pid
        unit_pid = None
        if self.args.service:
            r = self.command("B", "service_main_pid", self.args.service,
                ["systemctl", "show", "--property=MainPID", "--value", "--", self.args.service])
            if r["status"] == "ok" and r["output"].strip().isdigit():
                unit_pid = int(r["output"].strip())
            if requested is None:
                requested = unit_pid
        names, coverage = listed("/proc", 131072)
        candidates = []
        for index, name in enumerate(names):
            if index % 64 == 0:
                self.budget()
            if not name.isdigit():
                continue
            comm = (safe_read("/proc/" + name + "/comm", 256)[0] or "").strip()
            if comm in ("agave-validator", "solana-validato", "solana-validator", "jito-solana"):
                candidates.append(int(name))
        self.data["selection"].update(candidates=candidates, scan_coverage=coverage,
            declared_client=self.args.client, declared_commit=self.args.build_commit,
            declaration_is_binary_proof=False)
        if requested is None and not self.args.service and len(candidates) == 1:
            requested = candidates[0]
        if requested and requested in candidates:
            self.process = identity(requested)
        if not self.process:
            self.finding("C", "process_selection", "UNKNOWN", "validator",
                "No stable, recognizably named validator selected; wrappers and ambiguous matches are rejected.",
                "Use the actual validator PID and verify its executable provenance; host data remains usable.")
            return
        before = self.process
        self.data["selection"]["process"] = before
        cmd, reason = safe_read("/proc/%d/cmdline" % requested, 65536)
        self.flags = parse_flags((cmd or "").rstrip("\0").split("\0"))
        # Never persist unfiltered argv or keypair/endpoint arguments.
        visible = {k: v for k, v in self.flags.items() if k not in ("--log", "--ledger", "--accounts")}
        self.observation("C", "selected_flags", "validator", visible, "/proc/PID/cmdline whitelist", reason=reason)
        if identity(requested) != before:
            self.process = None
            self.finding("C", "process_selection", "UNKNOWN", "validator", "Process changed during selection.", "Repeat after a stable session.")
            return
        try:
            self.netns_ok = os.readlink("/proc/self/ns/net") == before["netns"]
        except OSError:
            self.netns_ok = False
        if not self.netns_ok:
            self.finding("A", "network_namespace", "UNKNOWN", "validator", "Audit and selected validator network namespaces are not verified identical.",
                         "Run the audit in the existing approved namespace; do not reconfigure or enter another namespace automatically.")
        if self.args.service and unit_pid != requested:
            self.finding("B", "service_binding", "UNKNOWN", self.args.service,
                "Service MainPID is not the selected validator; service policy is not attributed to it.",
                "Verify parent/cgroup membership and the correct unit manually.")
        claims = []
        for pid in candidates[:64]:
            p = identity(pid)
            f = parse_flags((safe_read("/proc/%d/cmdline" % pid, 65536)[0] or "").split("\0"))
            claims.append({"process": p, "interface": f.get("--xdp-interface"),
                           "queue_base": f.get("--xdp-queue-base"), "queue_width": None})
        self.observation("A", "peer_queue_claims", "co-located named validators", claims,
                         "whitelisted argv; width requires startup allocation evidence", reason="ok")
        self.finding("A", "queue_coexistence", "UNKNOWN", "selected path",
            "Queue base and CPU flags do not establish complete queue width/ownership; other applications may exist.",
            "Correlate exact per-NIC base+width, steering rules, XSK maps and current-session owners without modifying them.")

    def network(self):
        # Never pretend host namespace data describes a container's interface.
        if self.process and not self.netns_ok:
            return
        iface = self.args.interface or self.flags.get("--xdp-interface")
        origin = "explicit" if self.args.interface else "selected validator flag"
        if iface and not valid_iface(iface):
            self.finding("A", "interface_selection", "ERROR", "network", "Invalid configured interface name; no fallback silently substitutes another.", "Supply the exact safe interface name.")
            return
        if not iface:
            routes = [self.json_command("A", "default_routes_" + f, ["ip", "-j", "-" + f, "route", "show", "default"]) for f in ("4", "6")]
            rules = [self.json_command("A", "route_rules_" + f, ["ip", "-j", "-" + f, "rule", "show"]) for f in ("4", "6")]
            iface, origin = route_choice(routes[0], routes[1], rules[0], rules[1])
        if not iface or not Path("/sys/class/net", iface).exists():
            self.finding("A", "interface_selection", "UNKNOWN", "network", "No defensible interface selection: " + origin, "Use --interface after checking IPv4/IPv6 and policy routing.")
            return
        self.data["selection"]["interface"] = {"name": iface, "origin": origin}
        todo, seen = [iface], set()
        while todo and len(seen) < MAX_DEVICES:
            dev = todo.pop(0)
            if dev in seen or not valid_iface(dev):
                continue
            seen.add(dev)
            self.devices.append(dev)
            base = Path("/sys/class/net") / dev
            names, why = listed(base, 1024)
            lower = [n[6:] for n in names if n.startswith("lower_") and valid_iface(n[6:])]
            slaves = (safe_read(base / "bonding/slaves", 4096)[0] or "").split()
            todo.extend(x for x in lower + slaves if valid_iface(x))
            self.observation("A", "interface_stack", dev, {"lower": lower, "bond_members": slaves,
                "physical": (base / "device").exists(), "realpath": str(base.resolve())}, "sysfs", reason=why)
            for key in ("ifindex", "iflink", "operstate", "carrier", "mtu", "speed", "duplex", "device/numa_node",
                        "device/vendor", "device/device", "device/current_link_speed", "device/current_link_width"):
                self.read("A", "nic_" + key.replace("/", "_"), dev, base / key)
            if slaves:
                self.read("A", "bond_state", dev, "/proc/net/bonding/" + dev)
            for id_, args in (("driver", ["-i"]), ("link", []), ("channels", ["-l"]), ("features", ["-k"]),
                              ("rings", ["-g"]), ("coalescing", ["-c"]), ("rss", ["-x"]), ("steering_rules", ["-n"]), ("driver_stats", ["-S"])):
                if not (base / "device").exists() and id_ != "link":
                    continue  # Physical members supply queue/driver capabilities, not a virtual bond master.
                r = self.command("A", id_, dev, ["ethtool"] + args + [dev])
                if id_ == "features":
                    state = ntuple_state(r["output"]) if r["status"] == "ok" else "unavailable"
                    self.observation("A", "ntuple_state", dev, state, "ethtool -k", "prerequisite",
                                     reason="ok" if state != "unavailable" else r["status"] if r["status"] != "ok" else "missing_feature")
                if id_ == "channels":
                    self.observation("A", "channel_counts", dev, parse_channels(r["output"]) if r["status"] == "ok" else None,
                                     "ethtool -l", "configuration", "queues", "ok" if r["status"] == "ok" else r["status"])
            queues, why = listed(base / "queues", 4096)
            if why != "ok":
                self.data["coverage"].append("queue inventory %s: %s" % (dev, why))
            for queue in queues[:256]:
                if not re.fullmatch(r"(?:rx|tx)-\d+", queue):
                    continue
                # XPS belongs under TX queues, RPS under RX queues.
                keys = ("rps_cpus", "rps_flow_cnt") if queue.startswith("rx-") else ("xps_cpus", "xps_rxqs")
                for key in keys:
                    text, reason = safe_read(base / "queues" / queue / key, 18432)
                    parsed = sorted(mask_cpus(text)) if key.endswith("cpus") and mask_cpus(text) is not None else text
                    self.observation("A", key, dev + "/" + queue, parsed, str(base / "queues" / queue / key),
                                     unit="CPU IDs" if key.endswith("cpus") else "text", reason=reason)
            if len(queues) > 256:
                self.data["coverage"].append("queue details capped at 256 per interface")
            irqs, why = listed(base / "device/msi_irqs", 1024)
            if why != "ok":
                self.data["coverage"].append("NIC IRQ enumeration %s: %s" % (dev, why))
            for irq in irqs:
                if irq.isdigit():
                    self.nic_irqs.add(irq)
                    for key in ("smp_affinity_list", "effective_affinity_list"):
                        self.read("A", key, dev + "/IRQ" + irq, "/proc/irq/" + irq + "/" + key, unit="CPU list")
        if todo:
            self.data["coverage"].append("interface graph exceeded 16 nodes")
        self.command("A", "link_attachment", iface, ["ip", "-details", "link", "show", "dev", iface])
        self.command("A", "bpf_attachment", "audit network namespace", ["bpftool", "net", "show"])
        self.command("A", "xdp_sockets", "audit network namespace", ["ss", "-A", "xdp", "-a", "-n", "-p"])
        self.finding("A", "bonding_relevance", "INFO" if len(self.devices) > 1 else "NOT_APPLICABLE", iface,
            "Layered interface/bond evidence requires per-member analysis." if len(self.devices) > 1 else "No lower interface or bond member observed for this path.",
            "Assess existing redundancy and failure domains; do not add bonding as an assumed latency optimization.")
        self.finding("A", "hardware_readiness", "UNKNOWN", iface,
            "Feature state, driver, channels and existing rules are prerequisites; a new rule or zero-copy bind was not attempted.",
            "Match NIC/driver/kernel to vendor and exact-client requirements; inspect physical members and current successful allocation evidence.")
        self.finding("A", "filtering_boundary", "UNKNOWN", iface,
            "AF_XDP redirected traffic can bypass later kernel-stack filtering; existing firewall rules alone do not prove equivalent enforcement.",
            "Review the exact XDP steering/filter code and application rate limits against current firewall intent; never disable filtering for speed.")

    def capabilities(self):
        if not self.process:
            self.finding("B", "fresh_start", "UNKNOWN", "validator", "No stable process binding.", "Select the actual validator.")
            return
        pid = self.process["pid"]
        exe = "/proc/%d/exe" % pid
        for label, path in (("running_inode", exe), ("next_path", self.process["exe_path"].removesuffix(" (deleted)") if hasattr(str, "removesuffix") else self.process["exe_path"].replace(" (deleted)", ""))):
            try:
                s = os.stat(path)
                info = {"dev": s.st_dev, "inode": s.st_ino, "uid": s.st_uid, "gid": s.st_gid,
                        "mode": oct(stat.S_IMODE(s.st_mode)), "size": s.st_size, "mtime_ns": s.st_mtime_ns}
                try:
                    info["file_caps"] = decode_file_caps(os.getxattr(path, "security.capability"))
                    reason = "ok"
                except OSError as e:
                    info["file_caps"] = {"permitted": [], "inheritable": [], "effective_bit": False, "rootid": None} if e.errno == errno.ENODATA else None
                    reason = "ok" if e.errno == errno.ENODATA else errno.errorcode.get(e.errno, "xattr_unavailable")
                except ValueError:
                    info["file_caps"] = None
                    reason = "malformed_xattr"
                self.observation("B", "executable_permissions", label, info, path + " stat/security.capability", reason=reason)
            except OSError as e:
                self.observation("B", "executable_permissions", label, None, path, reason=errno.errorcode.get(e.errno, "unavailable"))
        for key in ("status", "limits", "uid_map", "gid_map", "attr/current", "cgroup"):
            self.read("B", "process_" + key.replace("/", "_"), "validator", "/proc/%d/%s" % (pid, key))
        self.command("B", "executable_mount", "next_path", ["findmnt", "-n", "-o", "TARGET,FSTYPE,OPTIONS", "--target", self.process["exe_path"].replace(" (deleted)", "")])
        if self.args.service:
            props = "Id,MainPID,User,Group,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,RestrictAddressFamilies,PrivateNetwork,PrivateUsers,LimitMEMLOCK,LimitRTPRIO,LimitNICE,Nice,CPUAffinity,AllowedCPUs,CPUQuotaPerSecUSec,SystemCallFilter,MemoryMax,TasksMax,ProtectKernelTunables"
            self.command("B", "service_policy", self.args.service, ["systemctl", "show", "--property=" + props, "--no-pager", "--", self.args.service])
        tasks, reason = listed("/proc/%d/task" % pid, MAX_TASKS)
        self.data["coverage"].append("thread capability inventory: " + reason)
        for tid in tasks:
            if not tid.isdigit():
                continue
            text, why = safe_read("/proc/%d/task/%s/status" % (pid, tid), 65536)
            selected = {k: v.strip() for k, v in (line.split(":", 1) for line in (text or "").splitlines() if ":" in line)
                        if k in ("Name", "CapEff", "CapPrm", "CapInh", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Cpus_allowed_list", "Mems_allowed_list")}
            self.observation("B", "thread_privileges", tid, selected if text is not None else None, "/proc/PID/task/TID/status", reason=why)
        if self.args.client == "unknown":
            level, message = "UNKNOWN", "Installed implementation is unidentified; compatibility remains unverified."
        elif self.args.client != "reference_xdp":
            level, message = "NOT_APPLICABLE", "reference XDP profile capability recipe is not applied to this declared client; exact build remains unverified."
        elif self.flags.get("--no-xdp") is True:
            level, message = "NOT_APPLICABLE", "Selected argv explicitly disables XDP; other client niceness requirements still need review."
        else:
            level, message = "UNKNOWN", "Comparing against supplied reference XDP profile requirements only; the running binary build has not been authenticated."
        self.finding("B", "reference_xdp_requirements", level, "declared client", message,
            "Compare against the supplied reference XDP profile requirements; absent flags do not establish defaults for an unidentified binary.")
        self.finding("B", "fresh_start", "UNKNOWN", "next execution",
            "File xattrs, current capabilities and startup readiness are distinct. Ambient/bounding sets, pre-exec NNP, nosuid, namespaces, LSM and BPF policy can constrain startup.",
            "Resolve source/build identity and service binding, then use an approved maintenance validation. Do not restart merely to audit.")
        self.finding("B", "runtime_privileges", "INFO", "current threads",
            "Main-thread CapEff=0 or runtime NoNewPrivs=1 can be intentional after setup. Thread retention and adopted XDP state need exact-source correlation.",
            "Match neighbor-maintenance thread and current-session logs; do not infer fresh-start readiness or grant broad capabilities.")
        self.finding("B", "replacement_readiness", "UNKNOWN", "after upgrade/reboot",
            "Running inode and deployment path are observed separately; file changes do not modify the current process.",
            "Verify the new binary's provenance, capability xattr, policy and protocol compatibility before an approved restart.")

    def family(self, name, collect):
        self.budget()
        wall, start = utc(), time.monotonic()
        try:
            values, reason, token = collect()
        except (OSError, ValueError, TypeError, IndexError) as e:
            values, reason, token = {}, "parser_or_read_error:" + type(e).__name__, None
        return {"family": name, "start_utc": wall, "end_utc": utc(), "mono_start_s": start,
                "mono_end_s": time.monotonic(), "values": values, "reason": reason, "identity": token}

    def snapshot(self):
        self.budget()
        snapshot = {}
        def cpu():
            text, reason = safe_read("/proc/stat")
            return parse_cpu(text), reason, (safe_read("/sys/devices/system/cpu/online", 4096)[0])
        snapshot["cpu"] = self.family("cpu", cpu)
        def counters(path, parser=integers):
            text, reason = safe_read(path)
            return parser(text), reason, None
        vm_keys = {"pgmajfault", "pswpin", "pswpout", "oom_kill", "pgscan_direct", "pgscan_kswapd", "allocstall_normal", "nr_dirty", "nr_writeback"}
        snapshot["vmstat"] = self.family("vmstat", lambda: counters("/proc/vmstat", lambda t: {k:v for k,v in integers(t).items() if k in vm_keys}))
        for resource in ("cpu", "memory", "io"):
            def psi(r=resource):
                text, reason = safe_read("/proc/pressure/" + r, 65536)
                out = {}
                for line in (text or "").splitlines():
                    match = re.match(r"(some|full).*\btotal=(\d+)\b", line)
                    if match:
                        out[match[1]] = int(match[2])
                return out, reason, None
            snapshot["psi_" + resource] = self.family("psi_" + resource, psi)
        def memory():
            text, reason = safe_read("/proc/meminfo", 65536)
            keys = ("MemAvailable", "SwapFree", "Dirty", "Writeback", "AnonHugePages", "HugePages_Total", "HugePages_Free", "Hugepagesize")
            return {k: v for k, v in integers(text).items() if k in keys}, reason, None
        snapshot["memory"] = self.family("memory", memory)
        if self.netns_ok or not self.process:
            snapshot["udp4"] = self.family("udp4", lambda: counters("/proc/net/snmp", parse_udp))
            snapshot["udp6"] = self.family("udp6", lambda: counters("/proc/net/snmp6", lambda t: parse_udp(t, True)))
            snapshot["softnet"] = self.family("softnet", lambda: counters("/proc/net/softnet_stat", lambda t: {c + "/" + k: v for c, row in parse_softnet(t).items() for k, v in row.items()}))
            def irq_counts():
                text, reason = safe_read("/proc/interrupts")
                parsed, cpu_ids = parse_irqs(text)
                out, labels = {}, {}
                for irq in self.nic_irqs:
                    row = parsed.get(irq)
                    if not row:
                        return {}, "selected_irq_missing", None
                    labels[irq] = row["label"]
                    out["irq"+irq] = sum(row["counts"].values())
                    for cpu_id, count in row["counts"].items():
                        out["cpu"+cpu_id] = out.get("cpu"+cpu_id, 0) + count
                return out, reason if out else "no_selected_nic_irqs", labels
            snapshot["irqs"] = self.family("irqs", irq_counts)
        for dev in self.devices:
            def nic(d=dev):
                base = Path("/sys/class/net") / d
                ident = {k: safe_read(base / k, 4096)[0] for k in ("ifindex", "iflink", "address")}
                ident["realpath"] = str(base.resolve())
                vals = {k: int_read(base / "statistics" / k)[0] for k in NIC_KEYS}
                after = {k: safe_read(base / k, 4096)[0] for k in ("ifindex", "iflink", "address")}
                after["realpath"] = str(base.resolve())
                return vals, "ok" if ident == after and all(ident[k] is not None for k in ("ifindex", "iflink", "address")) else "device_changed_or_unavailable", ident
            snapshot["nic/" + dev] = self.family("nic/" + dev, nic)
        def disks():
            text, reason = safe_read("/proc/diskstats")
            out = {}
            for line in (text or "").splitlines():
                p = line.split()
                if len(p) >= 14 and not re.match(r"loop|ram|zram", p[2]) and re.fullmatch(r"[A-Za-z0-9_.-]+", p[2]):
                    # Major/minor plus diskseq guards same-name replacement when available.
                    seq, seq_reason = int_read("/sys/class/block/" + p[2] + "/diskseq")
                    out[p[2]] = {"identity": [p[0], p[1], seq], "identity_reason": seq_reason,
                                 "counters": [int(v) for v in p[3:14]]}
            return out, reason, None
        snapshot["disk"] = self.family("disk", disks)
        if self.process:
            def threads():
                pid = self.process["pid"]
                before = identity(pid)
                tasks, why = listed("/proc/%d/task" % pid, MAX_TASKS)
                out = {}
                for tid in tasks:
                    self.budget()
                    if not tid.isdigit():
                        continue
                    base = "/proc/%d/task/%s/" % (pid, tid)
                    begin = time.monotonic()
                    parsed = proc_stat(safe_read(base + "stat", 65536)[0])
                    sched, _ = safe_read(base + "schedstat", 4096)
                    if parsed:
                        parsed["read_start_s"], parsed["read_end_s"] = begin, time.monotonic()
                        p = (sched or "").split()
                        parsed["runqueue_ns"] = int(p[1]) if len(p) >= 2 and p[1].isdigit() else None
                    out[tid] = parsed
                after = identity(pid)
                stable = before == after == self.process
                return out if stable else {}, why if stable else "process_changed", before
            snapshot["threads"] = self.family("threads", threads)
        return snapshot

    def metric(self, area, id_, scope, value, unit, kind, before, after, reason="ok", denominator=None):
        self.budget()
        a = (before["mono_start_s"] + before["mono_end_s"]) / 2
        b = (after["mono_start_s"] + after["mono_end_s"]) / 2
        if b <= a:
            value, reason = None, "invalid_time_interval"
        row = {"area": area, "id": id_, "scope": scope, "value": value, "unit": unit, "kind": kind,
            "source": before["family"], "status": "measured" if reason == "ok" and value is not None else "unavailable",
            "reason": reason if reason != "ok" or value is not None else "missing_field",
            "start_utc": before["start_utc"], "end_utc": after["end_utc"], "mono_start_s": a, "mono_end_s": b,
            "window_s": b-a, "endpoint_read_span_s": [before["mono_end_s"] - before["mono_start_s"], after["mono_end_s"] - after["mono_start_s"]],
            "denominator": denominator}
        self.report.record("metric", row)
        key = area + ":" + id_ + ":" + scope
        if key not in self.data["series"]:
            if len(self.data["series"]) >= MAX_SERIES:
                raise BudgetExceeded("metric series limit")
            self.data["series"][key] = {"unit": unit, "kind": kind, "valid": 0, "invalid": 0,
                "min": None, "max": None, "last": None, "window_s": 0.0, "weighted_sum": 0.0, "reason_counts": {}}
        s = self.data["series"][key]
        if row["status"] == "measured":
            s["valid"] += 1
            s["min"] = value if s["min"] is None else min(s["min"], value)
            s["max"] = value if s["max"] is None else max(s["max"], value)
            s["last"] = value
            s["window_s"] += b-a
            if id_ not in ("disk_read_await", "disk_write_await"):
                s["weighted_sum"] += value * (b-a)
            else:
                s["weighted_sum"] = None
        else:
            s["invalid"] += 1
            s["reason_counts"][row["reason"]] = s["reason_counts"].get(row["reason"], 0) + 1

    def intervals(self, previous, current):
        for name in sorted(set(previous) | set(current)):
            a, b = previous.get(name), current.get(name)
            if not a or not b:
                self.data["coverage"].append("missing family:" + name)
                continue
            av, bv = a["values"], b["values"]
            why = "ok" if a["reason"] == b["reason"] == "ok" and a["identity"] == b["identity"] else "identity_or_read_coverage_changed"
            area = "A" if name.startswith(("nic/", "udp", "softnet", "irqs")) else "C"
            elapsed = (b["mono_start_s"] + b["mono_end_s"] - a["mono_start_s"] - a["mono_end_s"]) / 2
            if elapsed <= 0:
                why = "invalid_time_interval"
            keys = sorted(set(av) | set(bv))
            if not keys:
                self.metric(area, name, "family", None, "unknown", "observation", a, b, a["reason"] if a["reason"] != "ok" else b["reason"] if b["reason"] != "ok" else "empty_or_unsupported_schema")
            for key in keys:
                x, y = av.get(key), bv.get(key)
                reason = why if why != "ok" else "missing_field" if x is None or y is None else "ok"
                if name == "cpu":
                    result = cpu_percent(x, y) if reason == "ok" else None
                    for field in ("work", "iowait", "irq", "softirq", "steal"):
                        self.metric("C", "cpu_" + field, key, result[field] if result else None, "% CPU accounting", "interval_ratio", a, b,
                                    reason if reason != "ok" else "ok" if result else "reset_or_zero_denominator", "sum of first eight CPU tick deltas")
                elif name == "threads":
                    same = reason == "ok" and x["start"] == y["start"]
                    for field, unit, scale in (("ticks", "% one logical CPU", 100.0 / os.sysconf("SC_CLK_TCK")), ("runqueue_ns", "% elapsed waiting", 1e-7)):
                        local_a, local_b = dict(a), dict(b)
                        if x and y:
                            local_a.update(mono_start_s=x["read_start_s"], mono_end_s=x["read_end_s"])
                            local_b.update(mono_start_s=y["read_start_s"], mono_end_s=y["read_end_s"])
                        span = (local_b["mono_start_s"]+local_b["mono_end_s"]-local_a["mono_start_s"]-local_a["mono_end_s"])/2
                        valid = same and x.get(field) is not None and y.get(field) is not None and y[field] >= x[field] and span > 0
                        self.metric("C", "thread_" + field, key + "/" + (y or x or {}).get("name", "unknown"),
                                    (y[field]-x[field])*scale/span if valid else None, unit, "interval_ratio", local_a, local_b,
                                    "ok" if valid else "thread_reuse_missing_reset_or_time", "per-thread endpoint midpoint interval")
                elif name == "disk":
                    valid = reason == "ok" and x["identity"] == y["identity"] and x["identity_reason"] == y["identity_reason"] == "ok"
                    fields = ((0, "reads", "operations/s"), (2, "read_sectors", "512-byte sectors/s"), (4, "writes", "operations/s"), (6, "write_sectors", "512-byte sectors/s"), (9, "io_ms", "busy ms/s"), (10, "weighted_io_ms", "weighted ms/s"))
                    for idx, label, unit in fields:
                        d = y["counters"][idx] - x["counters"][idx] if valid else -1
                        self.metric("C", "disk_"+label, key, d/elapsed if valid and d >= 0 and elapsed > 0 else None, unit, "counter_rate", a, b,
                                    "ok" if valid and d >= 0 else "disk_identity_missing_or_reset")
                    self.metric("C", "disk_inflight", key, y["counters"][8] if y else None, "operations", "gauge", a, b,
                                "ok" if y else "missing_field")
                    for n, t, label in ((0, 3, "read_await"), (4, 7, "write_await")):
                        count = y["counters"][n]-x["counters"][n] if valid else -1
                        delay = y["counters"][t]-x["counters"][t] if valid else -1
                        self.metric("C", "disk_"+label, key, delay/count if count > 0 and delay >= 0 else None,
                                    "ms/operation mean", "interval_ratio", a, b, "ok" if count > 0 and delay >= 0 else "no_operations_reset_or_identity", "completed operation delta")
                elif name == "memory" or name == "vmstat" and key.startswith("nr_"):
                    self.metric("C", name+"_"+key, "host", y, "pages" if name == "vmstat" or key.startswith("HugePages_") else "KiB", "gauge", a, b, reason)
                else:
                    # Driver-specific names are intentionally absent from this path.
                    valid = reason == "ok" and type(x) is int and type(y) is int and y >= x
                    value = (y-x)/elapsed if valid and elapsed > 0 else None
                    unit = "events/s"
                    if name.startswith("nic/") and key.endswith("bytes"):
                        unit = "bytes/s"
                    elif name.startswith("nic/") and key.endswith("packets"):
                        unit = "packets/s"
                    elif name == "vmstat":
                        unit = {"pswpin":"pages/s", "pswpout":"pages/s", "pgscan_direct":"pages/s", "pgscan_kswapd":"pages/s",
                                "pgmajfault":"faults/s", "oom_kill":"kills/s", "allocstall_normal":"stalls/s"}.get(key, "events/s")
                    elif name == "irqs":
                        unit = "interrupts/s"
                    if name.startswith("psi_"):
                        value = value / 10000 if value is not None else None
                        unit = "% elapsed stalled"
                    self.metric(area, name.split("/")[0]+"_"+key, name.split("/",1)[-1] if "/" in name else "host namespace",
                                value, unit, "counter_rate", a, b, "ok" if valid else reason if reason != "ok" else "reset_or_wrap", "family endpoint midpoint interval")

    def log(self):
        if not self.args.log_file:
            self.finding("C", "log_coverage", "UNKNOWN", "validator", "No explicit operational log supplied; no journal or log file was opened automatically.", "Optionally provide --log-file /absolute/validator.log; review its privacy first.")
            return
        p = external_path(self.args.log_file, log=True)
        fd = open_external(p)
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("log is not regular")
            start = max(0, before.st_size - self.args.log_bytes)
            os.lseek(fd, start, os.SEEK_SET)
            raw = os.read(fd, min(self.args.log_bytes, before.st_size))
            after = os.fstat(fd)
            current = os.stat(p, follow_symlinks=False)
            stable = (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino)==(current.st_dev,current.st_ino) and after.st_size >= before.st_size
            if start:
                raw = raw.partition(b"\n")[2]  # remove incomplete leading record
            if not raw.endswith(b"\n"):
                raw = raw.rpartition(b"\n")[0]
            lines = raw.decode("utf-8", "replace").splitlines()
            selected, seen = [], set()
            for line in lines:
                if re.search(r"(?i)xdp|xsk|votor|bls|certificate|replay.slot|repair|oom|out.of.memory|fallback|timeout", line):
                    line = clean(line)
                    if line not in seen:
                        seen.add(line)
                        selected.append(line[:4096])
            self.observation("C", "log_excerpt", "explicit operational log", selected[-128:], "explicit log tail (max 128 matching complete unique lines)",
                             "unattributed_log", "text", "ok" if stable else "rotation_or_truncation")
            self.finding("C", "log_coverage", "UNKNOWN", "validator",
                "Log excerpts are not bound to this PID/start/inode. Timestamps and matching words alone do not establish a current session or metric unit.",
                "Export structured current-session startup and interval metrics with build, process start, source schema and clock provenance.")
        finally:
            os.close(fd)


# All remaining code is embedded in the same distributed .sh file.
def duration(value):
    value = max(0, math.ceil(value))
    return '%dm%02ds' % divmod(value, 60)


class Progress:
    """One lightweight heartbeat; never touches server state or the report."""
    def __init__(self, maximum):
        self.start = time.monotonic()
        self.end = self.start + maximum
        self.phase, self.sample_end = 'starting', None
        self.lock, self.done = threading.Lock(), threading.Event()
        self.enabled, self.tty = True, sys.stdout.isatty()
        self.worker = threading.Thread(target=self.heartbeat, daemon=True)

    def label(self, now=None):
        now = time.monotonic() if now is None else now
        left = self.end - now
        remaining = ('budget left ' + duration(left)) if left > 0 else 'budget exhausted; finishing/blocked read'
        if self.sample_end is not None:
            remaining = 'measurement left %s; %s' % (duration(self.sample_end-now), remaining)
        return '[%s elapsed | %s] %s' % (duration(now-self.start), remaining, self.phase)

    def say(self, text):
        with self.lock:
            if self.enabled:
                try:
                    print(('\r\033[K' if self.tty else '') + clean(text), flush=True)
                except (OSError, BrokenPipeError):
                    self.enabled = False

    def stage(self, phase):
        self.phase = phase
        self.say(self.label())

    def heartbeat(self):
        count = 0
        while not self.done.wait(1):
            count += 1
            with self.lock:
                if not self.enabled:
                    continue
                try:
                    if self.tty:
                        print('\r\033[K' + self.label(), end='', flush=True)
                    elif count % 5 == 0:
                        print(self.label(), flush=True)
                except (OSError, BrokenPipeError):
                    self.enabled = False

    def close(self):
        self.done.set()
        if self.worker.is_alive():
            self.worker.join(timeout=1.5)
        if self.tty:
            self.say('')


def create_report(path):
    """Exclusive new regular file. POSIX parent traversal uses no-follow dirfds."""
    p = Path(os.path.abspath(path))
    if p.suffix.lower() != '.txt' or not p.name or '..' in Path(path).parts:
        raise ValueError('report must be a new .txt file in an existing directory')
    if os.name != 'posix':
        # Only embedded tests use this fallback; the live collector is Linux-only.
        for part in (p.parent,) + tuple(p.parent.parents):
            if part.is_symlink():
                raise ValueError('symlink output parent')
        return p, open(p, 'x', encoding='utf-8', buffering=1)
    dirfd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in p.parent.parts[1:]:
            newfd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=dirfd)
            os.close(dirfd)
            dirfd = newfd
            s = os.fstat(dirfd)
            if os.geteuid() == 0 and (s.st_uid != 0 or (s.st_mode & 0o022 and not s.st_mode & stat.S_ISVTX)):
                raise ValueError('root output parent must be root-owned and protected; sticky /tmp is allowed')
        fd = os.open(p.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dirfd)
        return p, os.fdopen(fd, 'w', encoding='utf-8', buffering=1)
    finally:
        os.close(dirfd)


class Report:
    """One streaming plain-text file. No JSON, sidecars, folders or overwrites."""
    def __init__(self, path, progress):
        self.path, self.file = create_report(path)
        self.progress = progress
        self.written, self.failed = 0, False
        self.maximum, self.reserve = 8*1024*1024, 1024*1024
        self.finalizing = False

    def line(self, text='', live=False):
        text = clean(text) + '\n'
        size = len(text.encode('utf-8'))
        limit = self.maximum if self.finalizing else self.maximum-self.reserve
        if self.written + size > limit:
            raise BudgetExceeded('single report size limit')
        try:
            self.file.write(text)
            self.file.flush()
            self.written += size
        except OSError:
            self.failed = True
            raise
        if live:
            self.progress.say(text.rstrip())

    def record(self, kind, row):
        row = sanitized(row)
        if kind in ('metric', 'snapshot'):
            return  # Summaries retain measured units, intervals and invalid counts.
        if kind == 'finding':
            self.line('[%s] %s / %s: %s' % (row['level'], row['area'], row['scope'], row['message']), live=True)
            return
        if kind == 'command':
            self.line('\n[%s] %s / %s | %s | UTC %s | %.3fs' % (
                row['area'], row['id'], row['scope'], row['status']+':'+row.get('reason',''),
                row['start_utc'], row['mono_end_s']-row['mono_start_s']))
            self.line('Read-only command: ' + ' '.join(row['argv']))
            self.line(row['output'].rstrip() or '(no output)')
            if row['status'] != 'ok':
                self.progress.say('  UNKNOWN %s / %s: %s' % (row['scope'], row['id'], row['status']))
            elif row['id'] in ('driver','bpf_attachment','xdp_sockets'):
                lines=[x.strip() for x in row['output'].splitlines() if x.strip()]
                self.progress.say('  %s / %s: %s' % (row['scope'],row['id'],'; '.join(lines[:4])[:600] or '(no entries reported)'))
            return
        if kind == 'observation':
            if str(row['source']).startswith('command:'):
                return  # Already printed with command status; avoid duplicate dumps.
            value = row['value']
            rendered = json.dumps(value, ensure_ascii=True, sort_keys=True) if not isinstance(value,str) else value.rstrip()
            self.line('[%s] %s / %s | %s | %s | UTC %s\n  %s' % (
                row['area'],row['id'],row['scope'],row['status']+':'+row['reason'],row['unit'],row['end_utc'],rendered))
            if row['id'] in ('selected_flags','interface_stack','ntuple_state','channel_counts','nic_operstate','nic_carrier'):
                self.progress.say('  %s / %s: %s' % (row['scope'],row['id'],rendered[:600]))

    def checkpoint(self, data):
        self.file.flush()  # Compatibility seam; never creates another file.

    def close(self):
        try:
            self.file.close()
        except OSError:
            self.failed = True
            raise


def pretty(value):
    if value is None:
        return 'UNKNOWN'
    return '%.4g' % value if isinstance(value,(int,float)) else clean(value)


class Audit(CoreAudit):
    def interpreted_checks(self):
        """Interpret evidence without promoting requested/setup state to live RX."""
        rows = self.data['inventory']
        physical = {r['scope'] for r in rows if r['id']=='interface_stack' and isinstance(r['value'],dict) and r['value'].get('physical')}
        for r in rows:
            scope, value = r['scope'], r['value']
            if r['id']=='ntuple_state' and scope in physical:
                if value=='off_fixed':
                    self.finding('A','ntuple_check','WARN',scope,
                        'rx-ntuple-filter is off [fixed]: the reference hardware-steered receive path is unavailable on this member.',
                        'Check the driver/card support. TX-only operation may remain possible; this test never changes the feature.')
                elif value in ('on','on_fixed'):
                    self.finding('A','ntuple_check','OK',scope,
                        'rx-ntuple-filter is enabled. This prerequisite alone does not prove steering allocation or accelerated receive.',
                        'Read existing queue/rule and current-session activation evidence.')
                else:
                    self.finding('A','ntuple_check','UNKNOWN',scope,
                        'Receive steering state: %s; usable UDP-port steering has not been demonstrated.' % value,
                        'Inspect the reported read-only feature/driver result; no setting was changed.')
            if r['id']=='bond_state' and isinstance(value,str):
                mode = re.search(r'^Bonding Mode:\s*(.+)',value,re.M)
                compatible = bool(mode and re.search(r'802\.3ad',mode.group(1)))
                self.finding('A','bond_mode','OK' if compatible else 'UNKNOWN' if not mode else 'WARN',scope,
                    ('Bond mode matches the reviewed 802.3ad requirement.' if compatible else 'Bond mode is missing or differs from the reviewed 802.3ad implementation.') + ' Link failover was not tested.',
                    'Inspect each member and existing LACP partner/aggregator status; no link is toggled.')
                down = re.findall(r'Slave Interface:\s*(\S+)(?:(?!Slave Interface:)[\s\S])*?MII Status:\s*down',value)
                if down:
                    self.finding('A','bond_member_down','WARN',scope,'Reported down bond member(s): '+', '.join(down),
                        'Check cabling/link/partner evidence. The audit never changes bond membership or link state.')
            if r['id']=='executable_permissions':
                caps = value.get('file_caps') if isinstance(value,dict) else None
                if caps is None:
                    self.finding('B','file_caps_check','UNKNOWN',scope,'Executable file capabilities could not be read.',
                        'Check the reported permission/read error; no privileges were granted.')
                    continue
                present = set(caps.get('permitted',[]))
                self.report.line('  %s file-permitted capabilities: %s' % (scope,', '.join(sorted(present)) or '(none)'),live=True)
                if self.flags.get('--no-xdp') is True:
                    self.finding('B','file_caps_check','NOT_APPLICABLE',scope,'--no-xdp is explicit; XDP file capability comparison is skipped.',
                        'Nonzero niceness requirements are separate.')
                else:
                    missing = BASE_CAPS-present
                    self.finding('B','file_caps_check','INFO' if missing else 'OK',scope,
                        'Requested XDP file capability set: '+('absent from file-permitted set: '+', '.join(sorted(missing)) if missing else 'all four capabilities present.')+
                        ' This does not prove startup permissions or current RX/TX mode; service-granted capabilities and adopted state can differ.',
                        'Review the printed executable, service policy and current-session setup evidence. No capability is changed.')
                conditional = set()
                if not self.flags.get('--no-xdp') and self.flags.get('--xdp-chain-loading'):
                    conditional.add('cap_sys_admin')
                for flag in ('--rpc-niceness-adjustment','--snapshot-packager-niceness-adjustment'):
                    if flag in self.flags:
                        try:
                            if int(self.flags[flag]) != 0:
                                conditional.add('cap_sys_nice')
                        except (ValueError,TypeError):
                            self.finding('B','niceness_flag','UNKNOWN',flag,'Niceness value is unreadable or invalid.','Verify the existing launch arguments.')
                if conditional:
                    missing = conditional-present
                    self.finding('B','conditional_caps','INFO' if missing else 'OK',scope,
                        'Explicit flags additionally require '+', '.join(sorted(conditional))+' under the requested XDP capability profile; '+
                        ('absent from file-permitted set: '+', '.join(sorted(missing)) if missing else 'present in file-permitted set.')+
                        ' Runtime effective bits alone cannot verify how the process started.',
                        'Inspect existing service/launch policy; no privileges are granted.')
        binaries={r['scope']:r['value'] for r in rows if r['id']=='executable_permissions' and isinstance(r['value'],dict)}
        if 'running_inode' in binaries and 'next_path' in binaries:
            running,next_path=binaries['running_inode'],binaries['next_path']
            if (running.get('dev'),running.get('inode')) != (next_path.get('dev'),next_path.get('inode')):
                self.finding('B','binary_path_changed','WARN','validator executable',
                    'The running executable inode differs from the file currently at its deployment path.',
                    'Read the two capability records separately; next-start observations do not describe the currently running inode.')
        thread_rows=[r for r in rows if r['id']=='thread_privileges']
        retained=[]
        for r in thread_rows:
            v=r['value']
            if not isinstance(v,dict):
                continue
            try:
                caps=sorted(cap_names(int(v.get('CapEff',''),16)))
            except ValueError:
                continue
            if caps:
                retained.append('%s %s: %s' % (r['scope'],v.get('Name','?'),', '.join(caps)))
        self.report.line('  Thread capability records: %d; effective-capability holders: %d' % (len(thread_rows),len(retained)),live=True)
        for line in retained[:16]:
            self.report.line('    '+line,live=True)
        self.report.line('  Main-thread CapEff=0 can be normal after setup. File +p without +ep is not automatically a defect.',live=True)
        if self.flags.get('--no-xdp'):
            self.finding('A','requested_xdp','INFO','validator','--no-xdp is explicitly present in the selected command line.',
                'Existing stale attachments may still be visible; they are not removed.')
        else:
            self.finding('A','actual_rx_tx','UNKNOWN','validator',
                'Current accelerated RX, TX and zero-copy traffic are not established by flags, attached programs or capability presence alone.',
                'Check existing current-session port/bind/traffic records. No packets, BPF programs or AF_XDP probe sockets are generated.')
        if self.flags.get('--xdp-zero-copy'):
            self.finding('A','zero_copy_requested','INFO','validator','--xdp-zero-copy is requested; actual per-member successful zero-copy binds remain unverified. For builds that require this receive path, failure to establish its required RX path can prevent startup.',
                'Read existing successful bind records. Native XDP attachment is not zero-copy proof.')

    def sample(self):
        start=time.monotonic()
        self.report.progress.sample_end=start+self.args.seconds
        self.report.progress.stage('C - measuring network / CPU / memory / storage counters')
        previous=None
        target=start
        while True:
            self.budget()
            began=time.monotonic()
            before=identity(self.process['pid']) if self.process else None
            current=self.snapshot()
            after=identity(self.process['pid']) if self.process else None
            if self.process and before != self.process or self.process and after != self.process:
                raise RuntimeError('validator identity changed during measurement; stop attributing this window')
            self.sample_count+=1
            for name,family in current.items():
                if family['reason'] != 'ok':
                    note=name+': '+family['reason']
                    if note not in self.data['coverage']:
                        self.data['coverage'].append(note)
            if previous is not None:
                self.intervals(previous,current)
            previous=current
            self.collection_s+=time.monotonic()-began
            cpu=self.data['series'].get('C:cpu_work:cpu',{}).get('last')
            self.report.progress.say('  Sample %d | CPU work %s%% | measurement left %s' % (self.sample_count,pretty(cpu),duration(start+self.args.seconds-time.monotonic())))
            if time.monotonic()-start>=self.args.seconds:
                break
            target+=self.args.interval
            if target<=time.monotonic():
                target=time.monotonic()+self.args.interval
            time.sleep(max(0,min(target,start+self.args.seconds)-time.monotonic()))
        self.report.progress.sample_end=None
        self.data['sampling']={'seconds':time.monotonic()-start,'snapshots':self.sample_count,'interval_s':self.args.interval}

    def finish(self):
        for key,s in self.data['series'].items():
            if re.match(r'A:nic_(rx_dropped|tx_dropped|rx_errors|tx_errors):',key) and s['valid'] and s['max']>0:
                self.finding('A','fresh_events','WARN',key,'New interface loss/error counts occurred during this window.',
                    'Correlate the layer with driver/application counters; bond/member counts are not added.')
        self.report.line('\n===== INTERVAL MEASUREMENTS =====',live=True)
        self.report.line('Mean is time-weighted across valid intervals; max is maximum observed interval value. No latency percentiles are inferred.')
        self.report.line('Rates are per measured second. CPU host percentages use aggregate CPU ticks; thread percentages use one logical CPU. Disk await values are interval means, not I/O tails.')
        self.report.line('Device/layer counts overlap; do not sum bond+member or kernel+AF_XDP counters. Unrecognized driver counters are raw evidence only.')
        self.report.line('For readability: per-core CPU and detailed IRQ rates are omitted; only the busiest 12 thread CPU rows and nonzero/unknown disk rows are printed.')
        rows=[]
        for key,s in self.data['series'].items():
            area,metric,scope=key.split(':',2)
            # Keep the single report readable: aggregate CPU plus busiest thread
            # rows below. Omit idle disk rows and detailed IRQ interval rates.
            if metric.startswith('cpu_') and scope!='cpu':
                continue
            if metric.startswith('thread_') or metric.startswith('irqs_'):
                continue
            if metric.startswith('disk_') and s['valid'] and s['max']==0:
                continue
            mean=s['weighted_sum']/s['window_s'] if s['weighted_sum'] is not None and s['window_s']>0 else None
            row='%s %s / %s: mean=%s max=%s last=%s %s | valid=%d invalid=%d measured=%.2fs' % (
                area,metric,scope,pretty(mean),pretty(s['max']),pretty(s['last']),s['unit'],s['valid'],s['invalid'],s['window_s'])
            if s['invalid']:
                row+=' | reasons='+json.dumps(s['reason_counts'],sort_keys=True)
            rows.append((row,metric,scope))
        for row,metric,scope in rows:
            self.report.line(row,live=metric in ('cpu_work','cpu_iowait','memory_MemAvailable') or metric.startswith('nic_') and metric.endswith(('dropped','errors')))
        busiest=sorted(((k,s) for k,s in self.data['series'].items() if ':thread_ticks:' in k and s['valid']),key=lambda pair:pair[1]['max'],reverse=True)[:12]
        if busiest:
            self.report.line('\nBusiest observed validator threads (at most 12):',live=True)
            for k,s in busiest:
                self.report.line('  %s: mean=%s max=%s %% of one logical CPU; %d valid/%d invalid intervals' % (
                    k.split(':',2)[-1],pretty(s['weighted_sum']/s['window_s']),pretty(s['max']),s['valid'],s['invalid']),live=True)
        self.report.line('\n===== FINAL A / B / C CHECK SUMMARY =====',live=True)
        for area in ('A','B','C'):
            self.report.line('\n'+area+' - '+AREAS[area])
            matches=[f for f in self.data['findings'] if f['area']==area]
            for f in matches:
                self.report.line('[%s] %s: %s\n  Next check: %s' % (f['level'],f['scope'],f['message'],f['next_step']))
            if not matches:
                self.report.line('See interval measurements and coverage. No conclusion of healthy or unhealthy is implied.')
        self.report.line('\nCoverage: '+('; '.join(dict.fromkeys(self.data['coverage'])) or 'No additional collection gaps recorded.'))
        elapsed=time.monotonic()-self.started
        self.report.line('Collection: elapsed %.2fs; Python CPU %.3fs; snapshots %d; sampling work %.3fs; child utilities %d.' % (
            elapsed,time.process_time()-self.cpu_seconds_start,self.sample_count,self.collection_s,self.runner.calls))
        self.report.line('Python CPU excludes utility CPU. Sampling perturbs the host slightly; compare counter scope before drawing conclusions.')
        self.report.line('Execution: '+self.data['execution_status']+' | '+self.data.get('execution_reason','checks finished'),live=True)
        self.report.line('OK means a specific observed prerequisite matched; UNKNOWN means unavailable or unproven. Completed collection is not a server-health or performance verdict.')
        self.report.line('XDP acceleration is traffic-path and build dependent. Do not infer Votor/consensus acceleration from NIC attachments; verify the installed implementation. AF_XDP bypasses normal IP/UDP delivery, not all kernel/driver involvement.')
        self.report.line('Only this report was written. No capability, XDP attachment, queue, interface, service, validator or system setting was changed.',live=True)
        self.report.line('Reports contain operational host details. Review before sharing; redaction cannot recognize every unlabeled secret.')


def arguments(argv=None):
    class PrivateParser(argparse.ArgumentParser):
        def error(self,message):
            self.exit(2,'Invalid arguments. Use --help.\n')
    p=PrivateParser(description='One script, one text report. Read-only local XDP/bond/capability checks with live progress. Linux + Python 3.8+. No network requests, installs or changes.',
        epilog='Run as the ordinary validator operator first. Missing permissions are reported. --seconds is the measurement window; total runtime budget adds 120 seconds for checks. Slow kernel reads may exceed that cooperative budget. Existing output files are never replaced.')
    p.add_argument('--interface',help='e.g. bond0 or eth0; otherwise selected validator flag / unambiguous route')
    p.add_argument('--pid',type=int,help='actual validator PID; auto-selects only one unambiguous validator')
    p.add_argument('--service',help='optional exact systemd unit, e.g. validator.service')
    p.add_argument('--seconds',type=int,default=60,help='measurement window 5..1800 seconds; default 60')
    p.add_argument('--output',help='one NEW .txt file; default ./solana-xdp-check-<unique>.txt in the current working directory')
    p.add_argument('--log-file',help='optional absolute regular .log/.txt operational log; only last 256KiB, no symlinks')
    p.add_argument('--self-test',action='store_true',help='embedded synthetic checks; no validator/utility/network access')
    a=p.parse_args(argv)
    if a.interface and not valid_iface(a.interface) or a.pid is not None and not 1<=a.pid<=4194304:
        p.error('invalid selection')
    if a.service and not SAFE_SERVICE.fullmatch(a.service) or not 5<=a.seconds<=1800:
        p.error('invalid service or window')
    a.interval=min(5,a.seconds)
    a.max_runtime=a.seconds+120
    a.command_timeout=3
    a.max_output_mib=8
    a.client,a.build_commit='reference_xdp',None
    a.log_bytes=262144
    if not a.output:
        a.output=str(Path.cwd()/('solana-xdp-check-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]+'.txt'))
    return a


def self_tests():
    """Embedded synthetic regressions; no production collector is run."""
    class Tests(unittest.TestCase):
        def test_capabilities(self):
            raw=struct.pack('<IIIII',0x02000000,(1<<12)|(1<<13),0,(1<<6)|(1<<7),0)
            v=decode_file_caps(raw)
            self.assertEqual(set(v['permitted']),BASE_CAPS)
            self.assertFalse(v['effective_bit'])
        def test_malformed_caps(self):
            with self.assertRaises(ValueError): decode_file_caps(b'bad')
        def test_masks(self):
            self.assertIsNone(mask_cpus('-1'))
            self.assertEqual(mask_cpus('00000001,00000000'),{32})
        def test_ntuple(self):
            self.assertEqual(ntuple_state('rx-ntuple-filter: off [fixed]'),'off_fixed')
            self.assertEqual(ntuple_state('rx-ntuple-filter: on [fixed]'),'on_fixed')
        def test_flags_private(self):
            f=parse_flags(['agave-validator','--identity','secret.json','--xdp-interface','bond0','--xdp-zero-copy'])
            self.assertNotIn('--identity',f)
            self.assertTrue(f['--xdp-zero-copy'])
        def test_secret(self):
            self.assertEqual(clean('Authorization: Bearer abc\ncontinuation'),'[SENSITIVE_TEXT_REDACTED]')
        def test_cpu_guest(self):
            self.assertEqual(parse_cpu('cpu 1 2 3 4 5 6 7 8 100 200')['cpu'],[1,2,3,4,5,6,7,8])
        def test_cpu_reset(self):
            self.assertIsNone(cpu_percent([10]*8,[9]*8))
        def test_iface(self):
            self.assertFalse(valid_iface('--oops'))
            self.assertTrue(valid_iface('bond0'))
        def test_duration(self):
            self.assertEqual(duration(-2),'0m00s')
            self.assertEqual(duration(61),'1m01s')
        def test_cli(self):
            a=arguments(['--seconds','60','--interface','bond0'])
            self.assertEqual(a.max_runtime,180)
            self.assertEqual(a.interval,5)
        def test_single_file_exclusive(self):
            with tempfile.TemporaryDirectory() as d:
                progress=Progress(5)
                progress.enabled=False
                p=Path(d)/'report.txt'
                r=Report(str(p),progress)
                r.line('hello')
                r.checkpoint({})
                r.close()
                self.assertEqual([x.name for x in Path(d).iterdir()],['report.txt'])
                with self.assertRaises(FileExistsError): Report(str(p),progress)
                self.assertEqual(p.read_text(),'hello\n')
                if os.name=='posix': self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)
        def test_report_redaction(self):
            with tempfile.TemporaryDirectory() as d:
                progress=Progress(5)
                progress.enabled=False
                r=Report(str(Path(d)/'r.txt'),progress)
                r.line('password=do-not-print')
                r.close()
                self.assertNotIn('do-not-print',r.path.read_text())
        def test_budget_report(self):
            with tempfile.TemporaryDirectory() as d:
                progress=Progress(5)
                progress.enabled=False
                r=Report(str(Path(d)/'r.txt'),progress)
                r.maximum,r.reserve=20,10
                with self.assertRaises(BudgetExceeded): r.line('x'*20)
                r.finalizing=True
                r.line('partial')
                r.close()
        def test_progress_labels(self):
            p=Progress(180)
            self.assertIn('budget left 2m50s',p.label(p.start+10))
            p.sample_end=p.start+60
            self.assertIn('measurement left 0m50s',p.label(p.start+10))
            self.assertIn('exhausted',p.label(p.end+1))
        def test_progress_shutdown(self):
            p=Progress(180)
            p.enabled=False
            p.worker.start()
            p.close()
            self.assertFalse(p.worker.is_alive())
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Tests))
    return 0 if result.wasSuccessful() else 2


def main(argv=None):
    a=arguments(argv)
    if a.self_test:
        return self_tests()
    if not sys.platform.startswith('linux') or not hasattr(os,'WNOWAIT'):
        print('Live checks require Linux. Use --self-test for embedded synthetic checks.',file=sys.stderr)
        return 3
    os.umask(0o077)
    progress=Progress(a.max_runtime)
    report,audit=None,None
    code=0
    handlers={}
    def interrupt(signum,frame):
        raise KeyboardInterrupt()
    try:
        for sig in (signal.SIGINT,signal.SIGTERM):
            handlers[sig]=signal.signal(sig,interrupt)
        report=Report(a.output,progress)
        audit=Audit(a,report)
        # One countdown describes the entire run; sampling has its own countdown.
        progress.end=audit.deadline
        progress.worker.start()
        report.line('SOLANA XDP CHECK - '+utc(),live=True)
        report.line('Read-only. One report: '+str(report.path),live=True)
        report.line('Measurement %ds; total cooperative budget %ds. Checks may finish sooner; blocked kernel reads can overrun.' % (a.seconds,a.max_runtime),live=True)
        report.line('Checking the requested XDP capability/configuration profile; installed build and current per-port traffic mode remain unverified.')
        report.line('Evidence is streamed below; interpreted results and measurements follow, with a final summary at the end.')
        overall=audit.deadline
        # Reserve the requested sample window and a small final-write allowance.
        inventory_end=overall-a.seconds-5
        audit.deadline=audit.runner.deadline=inventory_end
        phases=[('Selecting validator',audit.select),('B - reading executable and thread capabilities',audit.capabilities),
                ('A - checking interfaces, bond members and XDP prerequisites',audit.network)]
        if a.log_file:
            phases.append(('Reading explicit log excerpt (session not authenticated)',audit.log))
        for title,step in phases:
            progress.stage(title)
            if time.monotonic()>=inventory_end:
                audit.data['coverage'].append('Skipped '+title+': check budget exhausted')
                code=2
                continue
            before=identity(audit.process['pid']) if audit.process else None
            if audit.process and before!=audit.process:
                raise RuntimeError('selected validator changed before check')
            try:
                step()
            except BudgetExceeded:
                audit.data['coverage'].append('Incomplete '+title+': inspection/output budget')
                code=2
            if audit.process and identity(audit.process['pid'])!=audit.process:
                raise RuntimeError('selected validator changed during check')
        progress.stage('Interpreting XDP and capability observations')
        audit.interpreted_checks()
        audit.deadline=audit.runner.deadline=overall-2
        audit.sample()
        audit.data['execution_status']='complete' if code==0 else 'partial'
        audit.data['execution_reason']='checks finished' if code==0 else 'some inspection checks exceeded the budget; see coverage'
    except KeyboardInterrupt:
        code=130
        if audit:
            audit.data.update(execution_status='interrupted',execution_reason='signal received; completed observations retained')
        progress.say('Interrupted; preserving the single report.')
    except (OSError,ValueError,RuntimeError,RecursionError) as e:
        code=2
        # Do not print arbitrary paths/tokens from exceptions.
        reason=('Output file already exists; choose a new --output name. Nothing was overwritten.' if isinstance(e,FileExistsError)
                else type(e).__name__+' while checking; see completed report/coverage')
        if audit:
            audit.data.update(execution_status='partial',execution_reason=reason)
        progress.say('Check could not finish: '+reason)
    finally:
        progress.close()
        if report:
            try:
                report.finalizing=True
                if audit:
                    audit.finish()
                report.close()
                progress.say('Report saved: '+str(report.path))
            except (OSError,RuntimeError,ValueError):
                code=2
                progress.say('Report could not be fully finalized. Retain its existing complete lines; check free space and permissions.')
                try: report.close()
                except OSError: pass
        for sig,handler in handlers.items():
            signal.signal(sig,handler)
    return code


if __name__=='__main__':
    raise SystemExit(main())

PY_SOLANA_XDP_SINGLE
