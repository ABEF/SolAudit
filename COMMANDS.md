# Individual validator checks — commands you can run separately

Choose a check below and run just that command in your Linux terminal. **You do not need to run or download the audit script.** Most commands return a snapshot; the CPU, memory and disk sampling commands run for about 10 seconds and stop themselves.

**Every command in this file is observational.** There are no setting changes, installs, capability grants, XDP resets, validator starts/restarts or network stress tests. Output goes to your terminal; these commands create no report file. Running diagnostics still uses resources, and ordinary OS effects such as access timestamps, caches and audit logs can occur. Variable assignments affect only your current shell.

Run as your normal validator operator. If a command is missing, unsupported or denied, mark that check **UNKNOWN**; that is not a failed performance test. Do not automatically add privileges or install tools to make every check work. Stop any individual check with **Ctrl+C** in its terminal.

Manual output is not automatically redacted. These commands also do not inherit the audit script's timeouts or identity safeguards. Keep operational output private and stop on an unexpected target or error.

This guide contains no tuning commands. The separate [README improvement recipes](README.md#manual-change-recipes-prerequisites-commands-rollback) explain possible changes, their prerequisites and rollback; they require a separately approved action.

- [Select your targets](#select-your-targets)
- [A — Network, XDP and bonds](#a--network-xdp-and-bonds)
- [B — Capabilities and startup permissions](#b--capabilities-and-startup-permissions)
- [C — CPU, memory, storage and time](#c--cpu-memory-storage-and-time)
- [What to check first](#what-to-check-first)
- [Repeat one check before and after](#repeat-one-check-before-and-after)

## Select your targets

Find interface names:

```sh
ip -brief link show
```

Find default routes and any bonds; these are three separate checks:

```sh
ip -4 route show default
```

```sh
ip -6 route show default
```

```sh
ip -details link show type bond
```

A **bond** combines physical network ports into a logical interface. The **bond master** is that logical name, often `bond0`; its **members** are the physical ports, such as `enp65s0f0` and `enp65s0f1`. If you have one ordinary physical interface, there is no bond to select. A bond is not automatically faster or better for a validator. LACP/802.3ad also requires compatible switch configuration. Do not create or change a bond for these checks. [Linux bonding documentation](https://docs.kernel.org/networking/bonding.html)

Find the validator PID without dumping its full arguments:

```sh
ps -eo pid,user,comm
```

Identify the real validator, not a launcher or shell. Process names can be truncated. If you already know its systemd unit, this can help:

```sh
systemctl show validator.service --property=MainPID,User,FragmentPath
```

Replace `validator.service` with your actual unit; some installations do not use systemd. A unit's MainPID may be a wrapper, so verify the executable below.

Set only the variables needed by your chosen check. **These values are examples: replace them with your actual values.** Keep this terminal open so the variables remain available.

```sh
IFACE='bond0'                 # Bond master, or the physical NIC when there is no bond
NIC='enp65s0f0'                # One physical NIC; inspect each bond member separately
VALIDATOR_PID='12345'         # Actual running validator process
UNIT='validator.service'     # Optional: the actual unit, if used
```

In commands below, `${NIC:?set NIC first}` means “use NIC, or stop this command if it is unset/empty.” It does not check whether you selected the right NIC.

Verify the selected process:

```sh
ps -p "${VALIDATOR_PID:?set VALIDATOR_PID first}" -o pid,user,lstart,comm
```

```sh
readlink "/proc/${VALIDATOR_PID:?set VALIDATOR_PID first}/exe"
```

Expected: the intended validator executable and start time. If it restarts during testing, stop comparing that session and select the new PID. These manual commands do not provide the script's continuous identity checks.

Before attributing network output to that validator, compare namespaces:

```sh
readlink /proc/self/ns/net "/proc/${VALIDATOR_PID:?set VALIDATOR_PID first}/ns/net"
```

Expected: matching `net:[number]` values. If different, commands in this terminal inspect another network namespace; do not treat them as the validator's network. A denied read is UNKNOWN.

## A — Network, XDP and bonds

### A1. Selected interface state and existing XDP attachment

```sh
ip -details link show dev "${IFACE:?set IFACE first}"
```

**Look for:** intended interface, MTU, `UP`/`LOWER_UP`, and any XDP attachment/program information. An attachment is configuration evidence, not proof of live validator RX/TX or zero-copy. For a bond, repeat with each physical member as well; programs may be attached there.

### A2. Bond mode and physical members — only if you have a bond

```sh
cat "/proc/net/bonding/${IFACE:?set IFACE to the bond master}"
```

**Look for:** Bonding Mode, member names, MII Status, Link Failure Count and any aggregator/LACP details. Intended working links should be up; a historical failure count alone is not a current failure. Expected active/standby behavior depends on the bond mode. Confirm the exact validator build supports your mode; this output cannot prove failover works. Never disconnect links or bring them down as part of this check.

### A3. Physical link speed and negotiation

```sh
ethtool "${NIC:?set NIC to a physical member}"
```

**Look for:** Link detected, Speed and Duplex. Compare negotiated speed with your actual NIC and switch port. A down expected link or unexpected speed needs physical/network investigation. Virtual-interface or unsupported speed output is not a hardware diagnosis.

### A4. Driver, firmware and PCI identity

```sh
ethtool -i "${NIC:?set NIC first}"
```

**Look for:** driver, version, firmware-version and bus-info. These identify compatibility requirements; there is no universal “best” version implied by this check.

### A5. Receive-steering support and offload state

```sh
ethtool -k "${NIC:?set NIC first}"
```

**Look for:** `rx-ntuple-filter`. For the requested port-to-queue receive design, `on` is an enabled prerequisite; `off` needs investigation; `off [fixed]` cannot be enabled through this feature toggle. This does not prove every XDP implementation requires the same steering design. Do not enable or disable unrelated offloads from this output alone.

### A6. Current and maximum channel counts

```sh
ethtool -l "${NIC:?set NIC first}"
```

**Look for:** Current hardware settings versus Pre-set maximums, including Combined/RX/TX. Maximum is a capability, not a tuning target. Queue availability must cover the actual allocations. A queue-base value alone does not tell you the range width or prove non-overlap.

### A7. Existing receive-steering rules

```sh
ethtool -n "${NIC:?set NIC first}"
```

**Look for:** filters and queue actions for the actual traffic. Match them to current application allocation evidence. Missing/unsupported output is UNKNOWN; visible rules do not identify their owner reliably or prove packets matched them.

### A8. Existing RSS distribution

```sh
ethtool -x "${NIC:?set NIC first}"
```

**Look for:** receive hash and indirection table. Check against the actual queue layout. Explicit steering rules can override RSS for matching traffic, so an evenly distributed RSS table does not prove validator queues are balanced.

### A9. Ring sizes

```sh
ethtool -g "${NIC:?set NIC first}"
```

**Look for:** current versus maximum descriptor counts. Larger rings are not automatically better: investigate new no-buffer/ring-related loss and latency before considering a change.

### A10. Interrupt coalescing

```sh
ethtool -c "${NIC:?set NIC first}"
```

**Look for:** adaptive settings, usec delays and frame thresholds. Lower batching may reduce delay while increasing interrupt/CPU work. No single value is best across NICs and workloads. A polling AF_XDP path may behave differently from the ordinary interrupt-driven path.

The `ethtool` commands above query state. Letter case matters: retain the displayed options exactly. [ethtool manual](https://man7.org/linux/man-pages/man8/ethtool.8.html)

### A11. Interface errors and drops

```sh
ip -s -s link show dev "${NIC:?set NIC first}"
```

**Look for:** RX/TX errors, dropped, missed, CRC and carrier-related counters where available. Run this same command again after a known interval; investigate **new increments**, not merely old totals. Device replacement/reset invalidates a delta. Do not sum bond and member counters as independent losses.

### A12. Driver-specific counters

```sh
ethtool -S "${NIC:?set NIC first}"
```

**Look for:** the driver's queue/drop/no-buffer/error counters and, if provided, XDP counters. Names and meanings are driver-specific; some values are gauges. Compare the same counters twice under similar load. Zero generic NIC/kernel drops does not prove AF_XDP is loss-free. [Kernel network statistics](https://docs.kernel.org/networking/statistics.html)

### A13. BPF network attachments

```sh
bpftool net show
```

**Look for:** XDP attachments on the selected physical interfaces in this network namespace. Other entries may belong to TC or other applications. Permission errors are common under an ordinary account. Attachment presence alone cannot establish validator ownership or zero-copy mode.

### A14. Existing AF_XDP sockets

```sh
ss -A xdp -a -n -p
```

**Look for:** sockets, device/queue information where supported, and process ownership when visible. Older `ss` builds may not support this family. No output with limited permissions is insufficient proof that XDP is off. A socket's existence is not proof that the intended packets flow through it. AF_XDP binds a socket to a device/queue, but live RX/TX/zero-copy needs additional current-session evidence. [Kernel AF_XDP documentation](https://docs.kernel.org/networking/af_xdp.html)

### A15. Kernel UDP counters and socket queues

Run either check independently:

```sh
grep -E '^(Udp:|Udp6)' /proc/net/snmp /proc/net/snmp6
```

```sh
ss -u -a -n -m -p
```

**Look for:** new `RcvbufErrors`/`SndbufErrors`, attributable socket receive/send queues, and socket memory/drop information where exposed. In `/proc/net/snmp`, match the numeric row to its header row. Counters cover this network namespace, not only the validator. Kernel UDP statistics do not cover all AF_XDP traffic, and process details may be hidden.

## B — Capabilities and startup permissions

These checks inspect the permissions that exist now. They do not prove that a particular `setcap` command was typed previously. File permissions, startup policy and current thread privileges are different evidence.

### B1. Capabilities on the deployed binary

Use the absolute path of the actual regular executable file you verified earlier, not a symlink. Do not select a key/configuration file or leave a guessed example:

```sh
BIN='/absolute/path/to/agave-validator'
```

```sh
getcap -n -v "${BIN:?set BIN to the actual executable file}"
```

**Expected for the requested four-capability profile:** `cap_net_admin`, `cap_net_raw`, `cap_bpf`, `cap_perfmon` in the file-permitted set. The displayed order can differ. A result ending `=p` is compatible with the requested `+p`; `+ep` is not required by this profile. A pathname without a capability expression can mean no attribute **or an unsupported filesystem**, even with exit status 0; it is not by itself proof of missing permissions. Errors mean UNKNOWN. Namespace root IDs require matching launch context.

Compare the running executable with that deployment file:

```sh
stat -Lc 'device=%d inode=%i owner=%U:%G mode=%a %n' "/proc/${VALIDATOR_PID:?set VALIDATOR_PID first}/exe" "${BIN:?set BIN first}"
```

Matching device/inode pairs identify the same file at this check. If they differ, the deployed path and running executable are different; interpret them separately. A replaced executable does not change the already running process's acquired privileges.

**Do not use plain `getcap /proc/PID/exe` as proof:** `getcap` skips symlinks, including this process link. Use the actual regular deployment file above, or B2 for the exact running inode. [getcap manual](https://man7.org/linux/man-pages/man8/getcap.8.html), [libcap getcap implementation](https://kernel.googlesource.com/pub/scm/libs/libcap/libcap/+/refs/heads/master/progs/getcap.c)

### B2. Four-capability check on the exact running executable

This optional, independent command uses Python's standard library to read the running executable's capability attribute. It executes no validator code and writes no file. It is useful when the deployment path changed or you want a separate check for the running inode.

```sh
python3 -I -B - "${VALIDATOR_PID:?set VALIDATOR_PID first}" <<'PY'
import errno, os, struct, sys
pid = sys.argv[1]
if not pid.isdecimal() or int(pid) <= 0:
    raise SystemExit('Invalid PID')
try:
    raw = os.getxattr('/proc/' + pid + '/exe', 'security.capability')
except OSError as exc:
    if exc.errno == errno.ENODATA:
        raise SystemExit('No file capability attribute on the running executable')
    raise SystemExit('UNKNOWN: ' + str(exc))
if len(raw) < 4:
    raise SystemExit('UNKNOWN: malformed capability attribute')
magic = struct.unpack_from('<I', raw)[0]
revision = magic >> 24
if len(raw) != {1: 12, 2: 20, 3: 24}.get(revision):
    raise SystemExit('UNKNOWN: unsupported capability format')
permitted = struct.unpack_from('<I', raw, 4)[0]
if revision >= 2:
    permitted |= struct.unpack_from('<I', raw, 12)[0] << 32
for name, bit in [('cap_net_admin', 12), ('cap_net_raw', 13),
                  ('cap_bpf', 39), ('cap_perfmon', 38)]:
    print(name + ': ' + ('PRESENT' if permitted & (1 << bit) else 'MISSING'))
print('Full file-permitted mask:', hex(permitted))
print('File effective bit:', bool(magic & 1))
if revision == 3:
    print('Namespace root ID:', struct.unpack_from('<I', raw, 20)[0])
PY
```

**Interpretation:** four PRESENT lines establish this file-permitted prerequisite only. MISSING does not by itself prove broken XDP: launch policy or adopted state may matter. This command does not inventory/approve extra capabilities or prove actual packet reception. Runtime privileges can differ from the file attribute. [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

### B3. Current main-thread capabilities and lockdown

```sh
grep -E '^(Name|Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs|Seccomp):' "/proc/${VALIDATOR_PID:?set VALIDATOR_PID first}/status"
```

**Look for:** permitted/effective/bounding/ambient masks and runtime restrictions. `CapEff=0` and `NoNewPrivs=1` can be intentional after XDP setup. They do not prove startup lacked privileges. A hexadecimal mask is a capability bitmap, not a count.

For readable current capability names, if `getpcaps` already exists:

```sh
getpcaps "${VALIDATOR_PID:?set VALIDATOR_PID first}"
```

### B4. Individual thread privileges

```sh
grep -H -E '^(Name|CapPrm|CapEff|NoNewPrivs|Seccomp):' /proc/"${VALIDATOR_PID:?set VALIDATOR_PID first}"/task/*/status
```

**Look for:** thread IDs in the paths, names and effective masks. Unlike the main thread, a neighbor-maintenance thread may retain NET_ADMIN in the requested design. Verify the exact implementation before classifying that as unexpected. A vanished thread during this snapshot is a coverage gap, not evidence of zero privileges.

### B5. Actual process resource limits

```sh
cat "/proc/${VALIDATOR_PID:?set VALIDATOR_PID first}/limits"
```

**Look for:** Max locked memory, Max open files and scheduling-related limits. Compare with actual client requirements and demand. Neither `unlimited` everywhere nor an arbitrary large value is an established best practice.

### B6. Startup policy — only for your actual systemd unit

```sh
systemctl show "${UNIT:?set UNIT first}" --property=MainPID,User,Group,NoNewPrivileges,CapabilityBoundingSet,AmbientCapabilities,LimitMEMLOCK,LimitNOFILE,LimitNICE,LimitRTPRIO,RestrictAddressFamilies,SystemCallFilter,PrivateNetwork,PrivateUsers,CPUAffinity,AllowedCPUs,CPUQuotaPerSecUSec,MemoryMax,TasksMax
```

**Look for:** correct MainPID/launch relationship and policies compatible with intended setup. File capabilities can be limited by launch restrictions. Runtime lockdown in B3 is not the same as `NoNewPrivileges` imposed before executable startup. Ancestor cgroups and security policy can impose additional limits; this unit snapshot is not a full effective-resource audit. [systemd execution policy](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)

### B7. Binary mount and namespace mapping

Run either independently:

```sh
findmnt -n -o TARGET,FSTYPE,OPTIONS --target "${BIN:?set BIN first}"
```

```sh
cat "/proc/${VALIDATOR_PID:?set VALIDATOR_PID first}/uid_map" "/proc/$VALIDATOR_PID/gid_map"
```

**Look for:** `nosuid` and namespace mapping that may affect acquisition of file capabilities. `findmnt` here sees the terminal's mount namespace; a container may see a different mount. Do not remount or change namespace policy merely to clear an unknown result.

## C — CPU, memory, storage and time

These are server observations, not direct measurements of Solana consensus delay or Alpenglow finality. No RPC endpoint or vote-account balance is needed. Match host findings to existing validator telemetry before claiming a validator performance improvement.

### C1. CPU topology

```sh
lscpu -e=CPU,NODE,SOCKET,CORE,ONLINE
```

**Look for:** logical CPU IDs, physical cores and NUMA nodes. Two logical CPUs may share a physical core. Do not infer affinity settings from CPU numbering alone.

### C2. Physical NIC NUMA locality

```sh
cat "/sys/class/net/${NIC:?set NIC first}/device/numa_node"
```

**Look for:** the NIC's NUMA node, compared with C1 and current thread placement. `-1` means locality is not exposed; it is not a faulty NIC. Missing `device` often means you selected a virtual interface.

### C3. CPU load per logical CPU — about 10 seconds

```sh
mpstat -P ALL 1 10
```

**Look for:** individual busy CPUs, IRQ/softirq work, steal and idle. A low host average can hide one busy CPU. A polling worker near 100% is not automatically overloaded; correlate its role with actual delayed work.

### C4. Validator thread CPU — about 10 seconds

```sh
pidstat -t -u -p "${VALIDATOR_PID:?set VALIDATOR_PID first}" 1 10
```

**Look for:** busy thread IDs and names. Without `-I`, CPU percentage uses one logical CPU as its reference; a multithreaded process total can exceed 100%. Do not add the process total to its thread rows. Unsupported/denied process reads are UNKNOWN.

### C5. Thread CPU placement snapshot

```sh
ps -L -p "${VALIDATOR_PID:?set VALIDATOR_PID first}" -o pid,tid,psr,pcpu,comm
```

**Look for:** `PSR`, the CPU on which a thread last ran. This is not its allowed affinity mask, and `%CPU` here is lifetime-based rather than a fresh sampling interval.

Inspect allowed CPU/memory-node lists separately:

```sh
grep -H -E '^(Name|Cpus_allowed_list|Mems_allowed_list):' /proc/"${VALIDATOR_PID:?set VALIDATOR_PID first}"/task/*/status
```

**Look for:** allowed placement versus actual topology. A broad mask is not automatically wrong; a narrow mask is not automatically faster. Current placement does not prove absence of CPU throttling.

### C6. Memory capacity and headroom

```sh
free -h
```

**Look for:** `available` memory and swap totals/usage. Low `free` alone is normal when cache is useful. Swap used is not proof that swapping is happening now; use C7.

### C7. Memory pressure, swap and CPU summary — about 10 seconds

```sh
vmstat 1 11
```

**Look for:** the ten interval rows **after the first row**. The first row's rate/CPU values describe time since boot. Sustained `si`/`so` means active swap I/O; inspect run queue `r`, blocked tasks `b`, wait `wa` and steal `st` together. Persistent swapping or stalls under steady load needs investigation; it is not permission to disable swap or drop caches.

### C8. Resource-stall pressure

```sh
head -n 2 /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io
```

**Look for:** `avg10`, `avg60`, `avg300` percentages and `total` microseconds. `some` and `full` have different meanings and overlap; do not add them. Sustained memory/I/O `full` pressure with application delay is a stronger concern than a brief spike. System-wide CPU `full=0` is not proof of no CPU contention. Missing files mean unsupported/disabled, not zero. [Kernel PSI documentation](https://docs.kernel.org/accounting/psi.html)

### C9. Major faults, reclaim and OOM counters

```sh
grep -E '^(pgmajfault|pswpin|pswpout|oom_kill|pgscan_direct|pgscan_kswapd|allocstall)' /proc/vmstat
```

**Look for:** new increments between two readings. Any new OOM kill warrants cause/ownership investigation. Major faults during startup/catch-up can be expected; steady-state faults plus reclaim/stalls deserve closer inspection. Counters are host-wide and some names differ by kernel.

### C10. Storage devices and filesystem capacity

Run either independently:

```sh
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS
```

```sh
df -hT
```

**Look for:** the actual devices and usable free space. Older `lsblk` may need `MOUNTPOINT` instead of `MOUNTPOINTS`. Unexpectedly full filesystems need investigation; these commands do not authorize deleting ledger or snapshot data.

To identify the filesystem for a known ledger/accounts directory, replace this example path:

```sh
findmnt -T /absolute/path/to/ledger -o TARGET,SOURCE,FSTYPE,OPTIONS
```

Repeat for accounts if separate. Mapping a filesystem is not a disk-health test.

### C11. Storage activity and average latency — about 10 seconds

```sh
iostat -xz -y 1 10
```

**Look for:** the mapped device's `r_await`/`w_await` (mean milliseconds), `aqu-sz` (average queue length), traffic and `%util`. `-y` omits the initial since-boot report; `-z` omits inactive devices. Mean await is not p99, and 100% utilization does not by itself prove a parallel NVMe device is saturated. Avoid counting a partition/mapper device and its backing disk as independent work. Compare equivalent activity, including snapshot/catch-up context.

### C12. Time synchronization status

```sh
timedatectl show --property=NTPSynchronized --property=NTP --property=Timezone
```

**Look for:** expected synchronization/service state. This is status, not proof of acceptable offset or jitter. If chrony is already your time service, inspect its existing measurements:

```sh
chronyc tracking
```

**Look for:** reference, leap status, last/RMS offset and dispersion relative to your operating requirements. This queries the running time service; it does not set the clock. A missing chrony daemon does not mean every other time service is unsynchronized.

### C13. Recent validator log evidence — optional

For an actual systemd unit and selected PID:

```sh
journalctl --no-pager -u "${UNIT:?set UNIT first}" "_PID=${VALIDATOR_PID:?set VALIDATOR_PID first}" --since '10 minutes ago' -n 200
```

**Look for:** recent XDP setup/bind/fallback messages, queue allocation, errors, and existing validator outcome metrics. Match timestamps to the verified process start; PID reuse and incomplete logs limit attribution. Startup messages older than ten minutes will not appear here. If the validator logs only to a file, this journal can be empty.

For a known operational log file instead, replace this example path:

```sh
tail -n 200 -- /absolute/path/to/validator.log
```

Do not point this at key/configuration files. Logs can contain sensitive operational data; review before sharing. `xdp-network-config` values such as `exclusive`, `chained`, `adopted` or `off`, if emitted by your build, describe setup state. They do not alone prove current per-port traffic, receive acceleration or zero-copy.

## What to check first

You do not need to run every command. Choose the question you want answered:

| Your question | Start here | What would justify further investigation? |
|---|---|---|
| Did the requested file capabilities take effect? | B1; B2 if checking the running inode | Missing expected permissions after confirming the exact binary and startup model |
| Is XDP attached / are AF_XDP sockets present? | A1, A13, A14, then C13 | Denied or missing evidence, unexpected fallback, allocation failure; attachment alone is insufficient |
| Is the NIC suitable for the requested receive design? | A4–A8 | Unsupported required steering, incompatible queue allocation or driver/build support |
| Is my bond/link healthy? | A2, A3, A11, A12 on each member | New errors/failures or unexpected link/aggregator state |
| Is CPU placement or contention worth investigating? | C1–C5 and C8 | Persistent relevant worker delay or pressure under comparable workload |
| Is memory a problem? | C6–C9 | Sustained swapping/reclaim/stalls, inadequate headroom or new OOM kills |
| Is storage causing delays? | C10, C11 and C8 | Mapped-device latency/pressure increases alongside validator delay |
| Is the clock synchronized? | C12 | Unsynchronized state or unacceptable measured offset/dispersion |

Record **OK / investigate / UNKNOWN / not applicable**, the command, target and time. An unsupported check is UNKNOWN, not “bad.” These host checks cannot establish whether a consensus upgrade is active or independently measure slot lag/finality.

## Repeat one check before and after

1. Choose one metric and the exact interface/process/device. Note the workload and validator role.
2. Run its command; note values and time. For cumulative counters, take two readings over a known interval and calculate `(second - first) / seconds`.
3. This guide makes no changes. If a change is later explicitly approved, record the original value, intended improvement and rollback first.
4. Repeat the **same command**, duration and target under comparable workload after the change; reselect the PID after a separately approved restart.
5. Compare actual validator outcomes as well as host numbers. Better host numbers alone do not prove better validator performance. Counter resets, changed devices/builds, unequal load or missing outcome evidence make the comparison inconclusive.

No import or cleanup is needed for these terminal checks. Optional tools are only used if already present. There is no generated report to delete.

Prepared on 21 October 2026. All 55 shell examples passed Bash syntax checks; the running-inode decoder passed 11 synthetic cases, including missing/denied/unsupported attributes and capability revisions 1–3. Read-only command screening, navigation and local-link checks passed. Command semantics were independently reviewed against primary documentation. The commands have not been run on your production server. Sysstat measurement references: [mpstat](https://man7.org/linux/man-pages/man1/mpstat.1.html), [pidstat](https://man7.org/linux/man-pages/man1/pidstat.1.html), [iostat](https://man7.org/linux/man-pages/man1/iostat.1.html). Other references: [vmstat](https://man7.org/linux/man-pages/man8/vmstat.8.html), [bpftool net](https://github.com/libbpf/bpftool/blob/main/docs/bpftool-net.rst), [ss](https://man7.org/linux/man-pages/man8/ss.8.html).
