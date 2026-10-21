# Validator configuration and performance checks

This is the how-to for **[solana-xdp-check.sh](solana-xdp-check.sh)**. The script is self-contained, checks the local Linux server, displays progress and writes **one new text report in the directory you run it from**. This README is optional reading, not a script dependency.

To test individual items without running the script, use **[COMMANDS.md — individual read-only checks](COMMANDS.md)**. Each check includes its command, what to look for and how to interpret the result. It prints to the terminal and creates no report.

The script **does not tune anything**. It does not grant capabilities, reset XDP, change interfaces, load BPF programs, install packages, restart the validator or make RPC requests. Commands below marked **CHANGE** are manual examples for a specifically approved change. No production changes have been applied.

Start with the result, establish its cause, change one justified setting, and measure again. A missing observation is not proof that a setting needs changing. There is no universal best queue count, CPU mask, ring size or buffer size.

## Navigation

- [Run it and locate the report](#run-it-and-locate-the-report)
- [Does it check the four setcap capabilities?](#does-it-check-the-four-setcap-capabilities)
- [Read the result correctly](#read-the-result-correctly)
- [TODO: what to do first](#todo-what-to-do-first)
- [A — Network, XDP and bond checks](#a--network-xdp-and-bond-checks)
- [B — Capabilities and startup policy](#b--capabilities-and-startup-policy)
- [C — CPU, memory, storage and logs](#c--cpu-memory-storage-and-logs)
- [Manual change recipes: prerequisites, commands, rollback](#manual-change-recipes-prerequisites-commands-rollback)
- [Check whether a change actually helped](#check-whether-a-change-actually-helped)
- [Troubleshooting, scope and tests](#troubleshooting-scope-and-tests)

## Run it and locate the report

Requirements: Linux, Bash and Python 3.8+ standard library. Existing `ip`, `ethtool`, `bpftool`, `ss`, `systemctl` and `findmnt` improve coverage. Missing tools are reported; nothing is installed automatically.

Run as the normal validator operator first, from the directory where you want the report:

```sh
bash solana-xdp-check.sh
```

If you know the interface, specify it. For a bond, choose the **bond master**; the script discovers its members:

```sh
bash solana-xdp-check.sh --interface bond0
```

For precise selection, use the actual validator PID and, optionally, its systemd unit. These values are examples and must match your server:

```sh
bash solana-xdp-check.sh --pid 12345 --interface bond0 --service validator.service
```

The script auto-selects a process only when there is one recognized, unambiguous validator. A wrapper PID is not the actual validator PID. You can inspect names/PIDs without dumping the complete command line:

```sh
ps -eo pid,user,comm
ip -brief link show
# Only when this is your actual unit:
systemctl show validator.service --property=MainPID,User,FragmentPath,DropInPaths
```

Default measurement is **60 seconds**, sampled approximately every **5 seconds** after the initial checks. The total cooperative runtime budget is `--seconds + 120`; initial checks can finish earlier. The display distinguishes the remaining overall budget from the measurement countdown. A blocked kernel/filesystem read can overrun a userspace budget. The first CPU sample is UNKNOWN because calculating a rate needs two samples.

```sh
# Five-minute measurement; keep the same duration for before/after comparisons.
bash solana-xdp-check.sh --interface bond0 --seconds 300 --output ./before.txt
```

`--output` must name a **new** `.txt` file. An existing file is never overwritten. The directory must already exist and the output path must not contain symlink components. Without this option the name is `solana-xdp-check-<UTC-time>-<unique>.txt` in the current working directory, even if you invoked the script by an absolute path from somewhere else. The full report path is printed. Linux report mode is 0600.

Optional log reading is explicit and bounded:

```sh
bash solana-xdp-check.sh --interface bond0 --log-file /var/log/validator/validator.log
```

The supplied log must be a regular absolute `.log` or `.txt` file with no symlink components or sensitive filename. The script reads at most the last 256 KiB and keeps at most 128 matching complete, unique lines. It does not open a log automatically, read key files or dump process environments. Excerpts are **not authenticated as belonging to the current validator session**.

All options:

| Option | Purpose |
|---|---|
| `--interface NAME` | Explicit bond/master/NIC selection; otherwise validator flag, then conservative route detection |
| `--pid NUMBER` | Select the actual validator process |
| `--service NAME.service` | Read unit policy and check MainPID correspondence |
| `--seconds N` | Measurement window, 5–1800 seconds; default 60 |
| `--output PATH.txt` | One new report file; default current directory |
| `--log-file /absolute/file.log` | Read a limited operational log excerpt |
| `--self-test` | Run embedded synthetic tests; no live validator collection |
| `--help` | Show usage |

There are no `--client`, `--interval`, import or separate comparison-tool requirements in this simplified script. Root is optional. Do not grant extra privileges just to eliminate UNKNOWNs. If using a separately approved root read, its output directory must be root-owned and protected; a user-owned current directory may be refused. Use an existing approved root-owned working directory in that case. The script never silently redirects the report elsewhere.

## Does it check the four setcap capabilities?

**Yes.** It reads the executable's `security.capability` attribute and compares the file-permitted set with:

```text
cap_net_admin, cap_net_raw, cap_bpf, cap_perfmon
```

Look for these lines in section B:

```text
running_inode file-permitted capabilities: ...
next_path file-permitted capabilities: ...
[OK] ... Requested XDP file capability set: all four capabilities present. ...
```

This verifies the **resulting file permissions**, not shell history or whether you typed a particular command. `running_inode` is the executable used by the existing process; `next_path` is the file currently at its deployment path. They can differ after a binary replacement. If they differ, the report warns and their capability records must be read separately.

Your `+p` form is intentional: the script **does not require the file effective bit `+ep`**. A main thread with `CapEff=0` after setup is not automatically a defect. File-permitted capabilities, current thread capabilities and permissions available at the next startup are different checks.

An OK comparison means the four capabilities are present; it does not certify that any additional capabilities are justified. `getcap` commonly displays the resulting set as `cap_net_admin,cap_net_raw,cap_perfmon,cap_bpf=p`; ordering and `=p` display syntax can differ from the `+p` command you entered.

Missing file capabilities produce an **INFO** comparison, or UNKNOWN if they could not be read. They do not by themselves prove broken RX: launch policy may supply capabilities and existing compatible state may have been adopted. Conversely, all four being present does not prove actual XDP packet reception. See [B](#b--capabilities-and-startup-policy) and [recipe 1](#1-correct-a-proven-file-capability-gap).

## Read the result correctly

The file contains raw observations and command results first, interval measurements next, and the **FINAL A / B / C CHECK SUMMARY** at the end. The live terminal is a shorter view. Open the exact file shown by the script:

```sh
less ./before.txt
# Quick index into an explicitly named report:
grep -nE '\[WARN\]|\[UNKNOWN\]|\[ERROR\]|Execution:|Coverage:|FINAL A' ./before.txt
```

| Label | What it means | Your response |
|---|---|---|
| `OK` | This particular observed prerequisite matched the reference check | Keep it unless other evidence identifies a problem; this is not overall health |
| `INFO` | Configuration or a conditional comparison worth knowing | Read the explanation; no automatic change implied |
| `WARN` | A mismatch, new loss/error activity or another condition needs investigation | Establish cause and scope before choosing a change |
| `UNKNOWN` | Missing permission/tool/data, ambiguous selection, unsupported check, or insufficient proof | Fix visibility/selection if justified; do not replace it with an assumed zero |
| `NOT_APPLICABLE` | The check does not apply to the observed configuration | No change for that check |
| `ERROR` | Invalid input or a check that could not be performed as intended | Resolve that diagnostic error and collect again |

`observed:ok` on a raw field means the read worked, not that the setting is good. For commands, `ok:completed` means exit success; `unsupported_or_denied:nonzero_exit` combines several possibilities—read the actual command output. `unavailable`, `timeout` and `truncated` reduce evidence. The script uses roughly 3 seconds and 32 KiB per utility invocation.

For a metric such as:

```text
SYNTHETIC EXAMPLE — not your server:
A nic_rx_dropped / eth0: mean=2 max=6 last=0 events/s | valid=12 invalid=0 measured=60.01s
```

| Field | Meaning |
|---|---|
| `A`, `B`, `C` | Network/XDP; permissions; other server observations |
| Name and scope | The measured counter and exact device/host/thread; check the scope before attributing it to the validator |
| `mean` | Time-weighted average over valid intervals; for a gauge this weights sampled values, not continuous measurements |
| `max` | Largest measured interval rate/value, **not** maximum individual packet or I/O latency |
| `last` | Last valid measurement; it may precede later invalid intervals |
| Unit | `% CPU accounting`, `% one logical CPU`, `events/s`, `KiB`, etc.; these are not interchangeable |
| `valid`, `invalid` | Counts of intervals with usable/unusable measurements |
| `measured` | Sum of valid measurement spans, not necessarily the full requested duration |
| `reasons` | Why intervals were excluded: reset/wrap, changed identity, missing field, no operations, etc. |

In the example, drops occurred during the window even though the last interval was zero. The average is an event rate, not “2% packet loss.” A loss percentage requires a compatible denominator and driver semantics. No bond/member or overlapping error counters are added.

Disk `*_await` deliberately has `mean=UNKNOWN`: the script does not manufacture a pooled I/O mean from interval means. Its `max`/`last` still show interval-average milliseconds per completed operation. No operations in an interval normally makes that interval UNKNOWN. There are no p50/p95/p99 results in this report.

`Execution: complete` means the scheduled collection finished; WARNs and UNKNOWNs may still exist. Exit codes: 0 completed; 2 invalid arguments/partial/output failure/failed self-tests; 3 unsupported live platform or missing Python; 130 interrupted. `Ctrl+C` attempts to preserve the observations already written. A disk-write failure can prevent the final summary; keep complete existing lines.

## TODO: what to do first

This is your operational checklist. Unchecked items are not claims that your server is misconfigured.

- [ ] **P0 — Correct target:** verify PID, service, interface and physical bond members. Resolve conflicting selection/namespace observations.
- [ ] **P0 — Continuity:** investigate a down intended bond member, binary/path mismatch, known queue overlap, or established startup-permission gap.
- [ ] **P0 — Baseline:** save a complete report and record current client build, load/leader phase, traffic and existing validator outcome measurements.
- [ ] **P1 — Classify each WARN:** configuration defect, measured symptom, missing visibility, or unsupported feature. Assign it to A, B or C.
- [ ] **P1 — Choose one action:** record actual old values, causal hypothesis, new value, scope, risk, approval, rollback and acceptance criteria.
- [ ] **P1 — Recheck:** verify the new effective value, collect an equal-length after window, and compare actual validator outcomes as well as host counters.
- [ ] **P2 — Persistence:** only after acceptance, define the actual network/service/deployment configuration that owns the value; verify restart/reboot persistence during approved maintenance.
- [ ] **Monitoring gap:** obtain current-session RX/TX/zero-copy and per-port evidence if acceleration remains UNKNOWN.
- [ ] **Broader checks still separate:** CPU topology/NUMA, thermals/frequency, disk health, time sync, actual slot/replay/Votor/leader performance and effective cgroup limits.

Use this small record for each candidate change:

| Item | Fill in from your server |
|---|---|
| Report / UTC window / A-B-C | |
| Exact device, PID/thread, service or binary | |
| Observed problem and alternative causes | |
| Old value / proposed value / reason | |
| Expected improvement and acceptable regressions | |
| Approved change command and maintenance requirement | |
| Read-back command / before and after reports | |
| Rollback value and command | |
| Result | Keep / roll back / inconclusive |

## A — Network, XDP and bond checks

### Configuration and raw command sections

These are snapshots during the initial checks, not continuous monitoring. “Good” means consistent with your intended topology and supported implementation—not a universal maximum setting.

| Report field/section | What is tested; expected result | Suspicious or unknown; next step |
|---|---|---|
| `default_routes_4/6`, `route_rules_4/6` | Used only for interface auto-selection; a defensible, unambiguous route device | Different IPv4/IPv6 devices, policy routes or missing data: use a verified `--interface`; see recipe 0 |
| `selected_flags`, `peer_queue_claims` | Whitelisted XDP/niceness/thread arguments and other recognized validator claims | The base is not queue width; width is deliberately null. This does not inventory every other XDP application |
| `interface_stack` | `lower`, `bond_members`, physical-device presence and sysfs `realpath` | Expected members/layers should be present; missing membership needs configuration review |
| `nic_ifindex`, `nic_iflink` | Linux interface identity/link relationship | Names alone do not establish stable identity; changed devices invalidate comparison |
| `nic_operstate`, `nic_carrier` | Operational state and carrier (typically `up` and `1` for an intended active physical member) | Down/0: investigate cable, optic, switch and intended standby state; recipe 0 |
| `nic_mtu`, `nic_speed`, `nic_duplex` | MTU bytes, link speed Mbps, duplex | Match the network and hardware. Unknown speed on a virtual interface is not a fault. No automatic jumbo-MTU recommendation |
| `nic_device_numa_node` | NIC NUMA-node association | `-1` means no locality exposed, not a broken NIC. Map CPUs before affinity changes |
| `nic_device_vendor`, `nic_device_device` | PCI identifiers | Identification only; no performance score |
| `nic_device_current_link_speed`, `nic_device_current_link_width` | PCIe GT/s and lane width, distinct from Ethernet speed | Compare with card/slot capability; do not infer a fault from numbers without the hardware specification |
| `bond_state` | Bond mode, member MII/link state, failure counts and available LACP/aggregator information | The reference receive implementation checks 802.3ad. Another mode is a compatibility-review flag, not proof all XDP clients reject it. Mode OK does not prove failover or switch health |
| `driver` (`ethtool -i`) | Driver, firmware, bus metadata | Use exact driver/firmware when interpreting unsupported features; no automatic upgrade |
| `link` (`ethtool IF`) | Negotiation and link information | Compare supported/advertised/negotiated values; do not force speed/duplex on a live link as a generic fix |
| `channels`, `channel_counts` | `maximum` and `current` RX/TX/Combined/Other queue counts | “Maximum” is capability, not recommended count. Current queues must accommodate existing allocations; recipe 3 |
| `features`, `ntuple_state` | Receive steering prerequisite and offload state | `on`/`on_fixed`: enabled prerequisite only. `off`: mutable state needs review. `off_fixed`: no setting can enable this unsupported feature; recipe 2 |
| `rings` | Descriptor ring settings/limits | More buffering can raise latency. Change only after relevant driver ring/no-buffer loss; recipe 4 |
| `coalescing` | Interrupt batching/adaptive parameters | Less batching can lower delay but increase CPU/IRQ cost; recipe 4 |
| `rss` | Receive hash/indirection distribution | Check against owned queues. Do not overwrite the indirection table to “balance” it without ownership evidence |
| `steering_rules` | Existing rules steering flows to queues | Check actual port/queue ownership and overlap; do not clear rules or inject test filters; recipe 3 |
| `driver_stats` | One raw `ethtool -S` snapshot | Vendor/driver-defined counters; not necessarily counters, not measured deltas. Historical nonzero totals do not establish current loss |
| `rps_cpus`, `xps_cpus` | Kernel RX software-steering/TX CPU masks decoded to CPU IDs | Zero/empty can be intentional. These are not a proof of AF_XDP worker placement; recipe 5 |
| `rps_flow_cnt`, `xps_rxqs` | Flow-table size and TX mapping to RX-queue bitmap | `xps_rxqs` is a queue bitmap, **not CPU IDs**. Zero flow count can be intentional |
| `smp_affinity_list`, `effective_affinity_list` | Requested and effective selected-NIC IRQ CPUs | Mismatch may reflect managed IRQ/controller policy; inspect before changing; recipe 5 |
| `link_attachment`, `bpf_attachment` | Existing XDP attachment information | Presence does not establish process ownership, selected-port coverage, live packet traffic or zero-copy |
| `xdp_sockets` | Existing AF_XDP sockets and ownership where permitted | Missing permission/unsupported `ss` is UNKNOWN. Socket existence is not proof packets flowed |

The script queries hardware queue/features on physical members rather than treating a virtual bond master as a physical NIC. It does not bind test AF_XDP sockets or install steering rules. Linux describes separate RX/TX rings and the device/queue binding; these objects are prerequisites, not an end-to-end performance test. [Kernel AF_XDP documentation](https://docs.kernel.org/networking/af_xdp.html)

### Network measurements

| Printed metric | Meaning and desirable observation | When to investigate / action |
|---|---|---|
| `nic_rx_bytes`, `nic_tx_bytes` | Bytes/s on that interface; load indicator | More/less traffic alone is not better/worse. Compare equivalent load |
| `nic_rx_packets`, `nic_tx_packets` | Packets/s | Use with actual workload; accelerated paths and drivers can account differently |
| `nic_rx_dropped`, `nic_tx_dropped`, `nic_rx_errors`, `nic_tx_errors` | New drops/errors per second; ideally no unexplained new events | Positive values produce WARN. Locate layer/cause before buffers or rings; recipes 0, 4, 7 |
| `nic_rx_missed_errors`, `nic_rx_fifo_errors`, `nic_rx_over_errors` | Driver/device receive-loss-related event rates | Check precise driver meanings, ring pressure and CPU pressure together; recipe 4 only if supported by evidence |
| `nic_rx_crc_errors`, `nic_tx_carrier_errors` | Integrity/carrier-related event rates | Check physical path/link evidence; generic CPU or buffer tuning does not fix a bad optic/cable |
| `udp4_*`, `udp6_*` | Kernel UDP namespace-wide counter rates | `InErrors` overlaps some suberrors. `RcvbufErrors`/`SndbufErrors` suggest buffering/consumer issues but do not identify the validator socket; recipe 7 |
| UDP `InDatagrams`, `OutDatagrams`, `NoPorts`, `InCsumErrors`, `IgnoredMulti`, `MemErrors` when exported | Traffic delivered/sent; no listener; checksum; ignored multicast; memory-related errors | NoPorts/unrelated traffic can be harmless. Inspect socket/traffic attribution before classifying it as validator loss |
| `softnet_cpuN/processed`, `/drops`, `/squeezes` (or `rowN`) | Kernel receive work, backlog drops and processing-budget pressure, events/s | New drops deserve investigation. Squeezes are not dropped packets. Compare CPU/IRQ pressure and relevant kernel traffic; recipe 5 |

Kernel UDP and softnet values do not account for all AF_XDP losses. Clean kernel counters do not prove accelerated traffic is loss-free. Interface, bond/member and suberror counters overlap. [Kernel network statistics definitions](https://docs.kernel.org/networking/statistics.html)

The script leaves actual RX, TX and zero-copy traffic **UNKNOWN** when XDP is not explicitly disabled; independent evidence can inform your assessment but does not automatically clear this script finding. Merely requesting `--xdp-zero-copy`, observing a program, or passing the capability check cannot clear this. Existing startup/bind records and traffic-specific metrics must identify the current process, physical member, queue range and port. Setup modes such as `exclusive`, `chained` or `adopted` are setup claims, not throughput measurements.

## B — Capabilities and startup policy

| Field/section | Meaning; expected result | What to do with a mismatch |
|---|---|---|
| `service_main_pid` | MainPID from the explicitly requested unit | Must match the selected validator to attribute the unit directly. Wrappers require manual membership review |
| `executable_permissions` `dev`, `inode`, `uid`, `gid`, `mode`, `size`, `mtime_ns` | File identity, ownership, permissions, size and modification time; separate running inode and next path | Unexpected change/ownership requires investigation; a writable executable with privileges is a deployment concern, not a tuning target |
| `file_caps.permitted` | File-permitted capability names | The requested four-capability set should be present when that is the chosen startup model; recipe 1 |
| `file_caps.inheritable`, `effective_bit`, `rootid` | Other capability-set bits and namespace root mapping | Preserve their intended meaning. No `+ep` requirement is inferred; nonzero rootid needs namespace-specific review |
| `process_status` | Current process status, IDs, memory/scheduling fields and capabilities | Current state is not historical startup state; it must be read in context |
| `CapPrm`, `CapEff`, `CapInh`, `CapBnd`, `CapAmb` | Permitted, effective, inheritable, bounding and ambient capability bitmasks | Effective zero can be expected after setup. A bounding set can prevent a file-permitted capability from being acquired |
| `NoNewPrivs`, `Seccomp` | Runtime privilege-gain restriction and seccomp mode | Runtime lockdown can be expected; a restriction established **before exec** can affect initial capability acquisition |
| `process_limits` | Actual process limits, including locked memory, nice/priority and file descriptors | Compare actual client requirements and demand. Do not make every limit unlimited |
| `process_uid_map`, `process_gid_map` | User-namespace mapping | File caps in another namespace need matching scope; root within a container is not automatically host root |
| `process_attr_current` | Exposed security label/profile | Denial may require a narrowly scoped policy fix, not globally disabling the security mechanism |
| `process_cgroup` | Membership path only | **Not** measurement of effective cgroup CPU/memory throttling |
| `executable_mount` | Target mount, filesystem type and options | `nosuid` and namespace/mount policy can affect privilege acquisition; do not remount a production filesystem merely to clear UNKNOWN |
| `thread_privileges` | Per-thread Name, capability masks, NoNewPrivs, Seccomp, Cpus_allowed_list, Mems_allowed_list | The report prints effective-capability holders separately. A neighbor-maintenance thread may retain NET_ADMIN in the requested design; check exact thread/build context |
| `service_policy` | Only for `--service`: Id/User/Group, NoNewPrivileges, bounding/ambient caps, address families, namespaces, syscall filter, limits, affinity/quota/memory/tasks settings | Configured unit properties are not necessarily complete inherited/effective cgroup limits. Bind the unit to the real validator; recipe 6 |

Within `service_policy`, `LimitMEMLOCK`, `LimitRTPRIO`, `LimitNICE`, `Nice`, `CPUAffinity`, `AllowedCPUs`, `CPUQuotaPerSecUSec`, `MemoryMax` and `TasksMax` describe resource policy. `RestrictAddressFamilies`, `PrivateNetwork`, `PrivateUsers`, `SystemCallFilter` and `ProtectKernelTunables` describe isolation. Empty/unlimited/default values need the actual unit/kernel interpretation; none is automatically an optimization opportunity.

Conditional capability comparisons follow the configuration you supplied: chain loading adds `cap_sys_admin`; explicit nonzero RPC/snapshot-packager niceness adds `cap_sys_nice`. Omitted flags do not establish defaults on an unidentified build. Explicit `--no-xdp` skips the base XDP comparison while nonzero niceness remains separate. A forced receive/zero-copy mode may refuse startup when its required path cannot be established; this script does not test that by restarting.

File capabilities and their transformation at exec depend on other process and filesystem policy; inspect the whole launch path before correcting a gap. [Linux capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

## C — CPU, memory, storage and logs

These are basic host observations. Except selected validator threads, values are host-wide or device-wide and can include other workloads.

| Printed metric/section | Meaning and expected observation | When improvement may be justified |
|---|---|---|
| `cpu_work` | Aggregate CPU work as % of CPU-accounting ticks, including IRQ/softirq work | No universal target. High average can be fine; low average can hide one saturated critical thread |
| `cpu_iowait` | CPU-accounting I/O-wait share, not disk latency | Correlate with disk/PSI/application delay; do not blame storage from iowait alone |
| `cpu_irq`, `cpu_softirq` | Hard/soft IRQ accounting share | A sustained increase with network loss or delayed application work may justify placement review |
| `cpu_steal` | Hypervisor steal accounting | Material sustained increase can indicate host contention; guest tuning may not fix it |
| Busiest 12 validator threads | Mean/max CPU % of **one logical CPU**, with valid/invalid intervals | A polling thread near 100% is not automatically overloaded. Compare role, waiting and actual validator outcomes |
| `memory_MemAvailable` | Estimated available memory, KiB | Maintain workload-appropriate headroom. No fixed “keep X% free” rule |
| `memory_SwapFree` | Unused swap capacity, KiB | Zero alone cannot distinguish no swap from exhausted swap because SwapTotal is not printed. Check active swap rates too |
| `memory_Dirty`, `memory_Writeback` | Dirty/in-writeback memory, KiB | Persistent growth with I/O pressure/application stalls deserves investigation; bursts can be normal |
| `memory_AnonHugePages`, `memory_Hugepagesize` | Anonymous huge-page usage and configured huge-page size, KiB | Informational. Zero use is not itself a fault |
| `memory_HugePages_Total`, `memory_HugePages_Free` | Huge-page counts | Do not reserve huge pages without a client/workload requirement |
| `vmstat_pgmajfault` | Major faults/s | Startup/catch-up can fault pages; persistent activity with memory/IO pressure is more significant |
| `vmstat_pswpin`, `vmstat_pswpout` | Swap-in/out pages/s | Sustained swapping during steady validation is an investigation target; do not blindly run swapoff |
| `vmstat_pgscan_direct`, `vmstat_pgscan_kswapd`, `vmstat_allocstall_normal` | Reclaim scanning pages/s and allocation stalls/s | Compare with headroom and PSI; counts may be absent on a given kernel |
| `vmstat_oom_kill` | New OOM kills/s | Expected zero during a healthy steady window. Any event deserves prompt cause/ownership investigation |
| `vmstat_nr_dirty`, `vmstat_nr_writeback` | Page-count gauges | They are not rates. Page size is separate from KiB; compare with memory and storage pressure |
| `psi_cpu_some/full`, `psi_memory_some/full`, `psi_io_some/full` | % elapsed time with kernel-defined resource stalls over the interval | Compare comparable workload windows. Some/full are different and overlap; don't add them. Missing PSI is unsupported/unavailable, not zero |
| `disk_reads`, `disk_writes` | Completed operations/s | Load, not a score. Identify which actual device backs the validator data |
| `disk_read_sectors`, `disk_write_sectors` | 512-byte sectors/s, regardless of filesystem block size | Multiply by 512 for bytes/s. Don't sum partitions with their parent or stacked devices |
| `disk_io_ms` | Reported busy milliseconds/s | Not proof an NVMe is saturated at a particular percentage |
| `disk_weighted_io_ms` | Weighted I/O milliseconds/s | Indicates accumulated concurrent work/queueing; not a latency percentile |
| `disk_inflight` | Observed operations in flight, a gauge | More in-flight work can be throughput or queueing; judge with latency/outcomes |
| `disk_read_await`, `disk_write_await` | Per-interval mean ms/completed operation; overall mean intentionally UNKNOWN | Look for sustained increases at matched workload. Max is max interval mean, not worst individual I/O |
| `log_excerpt` | Bounded relevant log lines, only when requested | Stale session, rotation or incomplete records limit interpretation. Absence of a message does not prove absence of a problem |
| `Coverage`, collection overhead | Read/identity gaps, elapsed/Python CPU/sample work/utility count | Compare valid coverage and overhead. Python CPU excludes child utility CPU |

PSI describes kernel resource-stall time; the meanings of `some` and `full` differ and depend on resource/scope. System-wide CPU `full` is undefined and can be reported as zero for compatibility; that zero does not establish absence of CPU contention. [Kernel PSI documentation](https://docs.kernel.org/accounting/psi.html) Disk counters describe completed work and timing, not application latency tails. [Kernel I/O statistics](https://docs.kernel.org/admin-guide/iostats.html)

For readability the report omits per-core CPU rates, detailed IRQ rates, all per-thread run-queue-wait rates and valid-zero disk rows. Thread CPU is limited to the busiest 12. Raw driver statistics are a snapshot. The report does not map ledger/accounts paths to disks, measure disk health, scan kernel error history, inspect temperature/governors, verify time sync or determine exact validator lag.

## Manual change recipes: prerequisites, commands, rollback

**Do not run all recipes.** Choose the one supported by your report. `: "${VARIABLE:?description}"` checks for an unset/empty variable; it does not validate the value or stop an entire interactive paste by itself. CHANGE blocks below use a subshell with `set -euo pipefail` to stop on a missing variable or failed command. Run preparation/read commands carefully and stop on errors. Fill variables from your actual system, not arbitrary example numbers. Use `AUDIT_IFACE` for the original selected bond master/NIC, and `NIC` for the specific physical member being adjusted. Keep `AUDIT_IFACE` constant across before/after reports. Capture old values in your TODO record before a change; variables are not durable backups. A failure after a write does not undo it: inspect the effective state before retrying or rolling back. All **CHANGE** and **ROLLBACK** blocks require an approved scope; none is invoked by the diagnostic.

### 0. Resolve selection, link and visibility first

**Use when:** UNKNOWN process/interface, service mismatch or unexpected member state. **Expected improvement:** better attribution/visibility, not a claimed performance gain.

```sh
# READ ONLY: set names to actual values before using them.
: "${AUDIT_IFACE:?selected bond master or NIC}" "${VALIDATOR_PID:?actual validator PID}"
ip -details link show dev "$AUDIT_IFACE"
readlink "/proc/$VALIDATOR_PID/exe"
readlink "/proc/$VALIDATOR_PID/ns/net"
readlink /proc/self/ns/net
# For an actual bond only:
# cat "/proc/net/bonding/$AUDIT_IFACE"
bash solana-xdp-check.sh --pid "$VALIDATOR_PID" --interface "$AUDIT_IFACE"
```

A down link/CRC problem may need a cable, optic, switch or driver diagnosis rather than a tuning command. A different bond mode requires client compatibility and switch/network-owner review. There is no safe universal “fix bond” command for an unknown live management network. Do not bring interfaces down/up to test redundancy. Recheck the same member/link/error observations after a separately approved repair.

### 1. Correct a proven file-capability gap

**Use when:** the exact executable/startup model is verified and a required capability is absent from its intended startup permissions. **Not sufficient:** just seeing CapEff=0 or an INFO listing absent file caps.

```sh
# READ ONLY: use the actual deployment file, not a key/config file or guessed path.
: "${BIN:?absolute verified executable path}"
stat -Lc 'device=%d inode=%i owner=%U:%G mode=%a size=%s' "$BIN"
getcap -n "$BIN"
findmnt -n -o TARGET,FSTYPE,OPTIONS --target "$BIN"
```

Record the complete prior capability expression, whether the xattr was absent versus present-but-empty, and any namespace root ID. Confirm the binary identity again immediately before changing it. `setcap` writes a newly specified capability set; **`+p` is not a promise to preserve whatever other file capabilities already existed**. [setcap manual](https://man7.org/linux/man-pages/man8/setcap.8.html)

For an initial-namespace executable whose complete intended file set is exactly the four requested capabilities, the reviewed value is:

```sh
# PREPARE A VALUE ONLY. Use this only when it is the complete intended set.
APPROVED_CAP_TEXT='cap_net_admin,cap_net_raw,cap_bpf,cap_perfmon+p'
```

If required by verified flags/build, include SYS_ADMIN for chain loading and/or SYS_NICE for nonzero niceness in the **complete reviewed expression**. Preserve other justified permitted/inheritable/effective components. Nonzero namespace root IDs need a separately reviewed namespace-specific command; do not silently replace them with an initial-namespace xattr.

```sh
(
  set -euo pipefail
  : "${AUDIT_IFACE:?original selected interface}"
  : "${VALIDATOR_PID:?actual validator PID}"
  : "${BIN:?verified executable}"
  # CHANGE: approved exact binary and complete capability expression only.
  : "${BIN:?verified executable}" "${APPROVED_CAP_TEXT:?complete reviewed capability expression}"
  sudo setcap "$APPROVED_CAP_TEXT" "$BIN"

  # READ BACK: verify equality and inspect the file result.
  sudo setcap -v "$APPROVED_CAP_TEXT" "$BIN"
  getcap -n "$BIN"
  bash solana-xdp-check.sh --pid "$VALIDATOR_PID" --interface "$AUDIT_IFACE"
)
```

**Expected:** the intended file set matches. **This does not change permissions of the already-running process or prove faster traffic.** Startup validation is a separate approved maintenance action. Binary replacement can lose xattrs; deployment must re-verify them.

```sh
(
  set -euo pipefail
  : "${BIN:?verified executable}"
  # ROLLBACK OPTION A: old xattr existed; restore its exact reviewed expression.
  : "${OLD_CAP_TEXT:?complete old expression from the receipt}"
  sudo setcap "$OLD_CAP_TEXT" "$BIN"
  getcap -n "$BIN"
  # OPTION B, instead of A: ONLY if old state was verified to have NO xattr:
  # sudo setcap -r "$BIN"
)
```

Do not apply the no-xattr rollback to an old empty capability xattr; those states differ. Abort if file identity, namespace, desired set or existing deployment ownership is unresolved.

### 2. Receive steering is off

**Use when:** a physical member reports mutable `off`, the required hardware/driver support exists, and the exact queue/XDP owners' maintenance plan allows the change. **If `off [fixed]`: there is no enabling command.** Hardware/driver/client-path compatibility must be resolved separately.

```sh
# READ ONLY / SAVE: record this value and all existing steering rules.
: "${NIC:?verified physical member}"
ethtool -k "$NIC"
ethtool -n "$NIC"
OLD_NTUPLE=$(ethtool -k "$NIC" | awk '$1=="rx-ntuple-filter:" {print $2}')
```

Only use the next block after confirming the feature is mutable and preserving any existing filter ownership. Do not treat enabling steering as proof that the validator installed its receive rules.

```sh
(
  set -euo pipefail
  : "${NIC:?verified physical member}"
  : "${AUDIT_IFACE:?original selected interface}"
  : "${OLD_NTUPLE:?recorded old feature state}"
  case "$OLD_NTUPLE" in on|off) ;; *) exit 1;; esac
  # CHANGE: owner-aware maintenance only; may affect active filtering.
  sudo ethtool -K "$NIC" ntuple on
  # READ BACK:
  ethtool -k "$NIC"
  ethtool -n "$NIC"
  bash solana-xdp-check.sh --interface "$AUDIT_IFACE"
  # ROLLBACK: same approved maintenance/owner conditions; turning off can disrupt filters.
  # sudo ethtool -K "$NIC" ntuple "$OLD_NTUPLE"
)
```

**Expected:** feature on, ownership/rules preserved, then actual intended port activation established through current-session evidence. **Risk:** filter disruption; the client may already manage this setting at startup. **Persistence:** driver/network-manager/client dependent. Keep a healthy client-managed configuration unchanged. [ethtool feature controls](https://man7.org/linux/man-pages/man8/ethtool.8.html)

### 3. Queue sharing, zero-copy or validator startup flags

**Use when:** exact current allocations or startup records establish a mismatch. Required evidence is per-member **base plus width**, every competing owner, supported queue count, attachment ownership and intended port coverage.

```sh
# READ ONLY:
: "${NIC:?physical member}"
ethtool -l "$NIC"
ethtool -n "$NIC"
ethtool -x "$NIC"
ip -details link show dev "$NIC"
bpftool net show
ss -A xdp -a -n -p
```

`--xdp-queue-base` is a starting queue, not its width. Different bases can still overlap. `--xdp-cpu-cores` in the supplied configuration controls TX loops, not a universal RX/IRQ affinity setting. A zero-copy request needs actual driver/socket-mode support; native attachment is insufficient.

An approved flag change belongs in the existing validator launch configuration. Locate the actual file without printing a complete credential-bearing command line:

```sh
(
  set -euo pipefail
  # READ ONLY:
  : "${UNIT:?actual validator unit name}"
  systemctl show "$UNIT" --property=MainPID,FragmentPath,DropInPaths
  # CHANGE: only the previously reviewed existing argument/unit file:
  : "${LAUNCH_FILE:?exact existing launch configuration file}"
  sudoedit "$LAUNCH_FILE"
  # If an actual systemd unit/drop-in changed, reload its definitions after approval:
  # sudo systemctl daemon-reload
)
```

Prepare the exact before/after argument diff. Do not create a second validator command to test it. Queue-base, mode and worker flags normally require a startup to take effect; use your approved single-validator maintenance procedure, not an invented unit or blind restart. No generic `ethtool -L`, `ethtool -N`, XDP detach or `reset-xdp-interface` repair is supplied: those can break active sockets or another application's steering.

**Expected:** intended allocation and bind mode, all required paths active, no overlap/security regression, improved matched outcomes. **Rollback:** restore the exact old argument/configuration and supported allocation under the same continuity procedure. An adopted setup does not prove a clean fresh start will work. Zero-copy or more queues can worsen results or prevent startup; leave them unchanged without evidence.

### 4. Ring or interrupt-coalescing experiment

**Use when:** fresh, driver-understood ring/no-buffer loss or IRQ overhead correlates with the problem. Exact member, existing AF_XDP owners, supported values and disruption risk must be reviewed first. Larger rings and lower coalescing are not default improvements.

```sh
# READ ONLY: save complete outputs and chosen OLD_* values in the TODO receipt.
: "${NIC:?physical member}"
ethtool -g "$NIC"
ethtool -c "$NIC"
ethtool -S "$NIC"
```

Choose **one** experiment, not both together:

```sh
(
  set -euo pipefail
  : "${NIC:?verified physical member}"
  # CHANGE OPTION A: approved RX ring size; may interrupt/reconfigure live queues.
  : "${NEW_RX_RING:?approved supported descriptor count}" "${OLD_RX_RING:?recorded old RX descriptor count}"
  sudo ethtool -G "$NIC" rx "$NEW_RX_RING"
  ethtool -g "$NIC"
  # ROLLBACK A: sudo ethtool -G "$NIC" rx "$OLD_RX_RING"
)
```

```sh
(
  set -euo pipefail
  : "${NIC:?verified physical member}"
  # CHANGE OPTION B: approved fixed receive coalescing experiment.
  # Use only when adaptive RX is already off and this driver's coupled fields are understood.
  : "${NEW_RX_USECS:?approved supported microseconds}" "${OLD_RX_USECS:?recorded old receive coalescing value}"
  sudo ethtool -C "$NIC" rx-usecs "$NEW_RX_USECS"
  ethtool -c "$NIC"
  # ROLLBACK B: restore ALL changed/coupled fields from the recorded old state.
  # For a verified rx-usecs-only change: sudo ethtool -C "$NIC" rx-usecs "$OLD_RX_USECS"
)
```

**Recheck:** same-duration report, fresh driver counters with known semantics, path-specific losses, CPU pressure and actual validator delay. **Accept:** intended effective value and repeatable benefit without worse tails/participation. **Abort:** link/queue reset, filter loss, unexpected fallback or worse outcomes. More buffering can increase latency; less batching increases interrupt work. Persistence varies; don't add a boot script before validating the experiment.

### 5. IRQ or software-steering placement

**Use when:** actual topology and workload show that a specific vector/queue is contending on the relevant kernel path. Read-only topology is an additional step; the simple report does not print full topology or per-IRQ interval rates.

```sh
# READ ONLY, if these tools/files exist:
lscpu -e=CPU,NODE,SOCKET,CORE,ONLINE
: "${NIC:?physical member}" "${IRQ:?verified numeric IRQ}"
cat "/sys/class/net/$NIC/device/numa_node"
cat "/proc/irq/$IRQ/smp_affinity_list"
cat "/proc/irq/$IRQ/effective_affinity_list"
systemctl is-active irqbalance
```

Select online CPUs with suitable locality and headroom, preserving the actual managed-IRQ/irqbalance policy. Hyperthread siblings are not independent physical cores. A TX-loop flag is not an IRQ setting. [Kernel scaling guidance](https://docs.kernel.org/networking/scaling.html)

```sh
# PREPARE/SAVE, then CHANGE one approved vector only.
: "${IRQ:?verified numeric IRQ}" "${NEW_CPULIST:?approved online CPU list}"
IRQ_PATH="/proc/irq/$IRQ/smp_affinity_list"
OLD_CPULIST=$(cat "$IRQ_PATH")
: "${OLD_CPULIST:?old affinity was not readable}"
(
  set -euo pipefail
  : "${IRQ:?verified numeric IRQ}" "${IRQ_PATH:?verified IRQ path}" "${NEW_CPULIST:?approved CPU list}" "${OLD_CPULIST:?saved old list}"
  case "$IRQ" in ''|*[!0-9]*) exit 1;; esac
  printf '%s\n' "$NEW_CPULIST" | sudo tee "$IRQ_PATH" >/dev/null
  cat "/proc/irq/$IRQ/effective_affinity_list"
  # ROLLBACK: printf '%s\n' "$OLD_CPULIST" | sudo tee "$IRQ_PATH" >/dev/null
)
```

`sudo tee` elevates the write; `sudo printf ... > /proc/...` would not elevate the shell's redirection. A controller can reject a CPU mask and irqbalance can overwrite manual placement; verify the effective result. Do not globally stop irqbalance as a diagnostic. [Kernel IRQ affinity](https://docs.kernel.org/core-api/irq/irq-affinity.html)

For an independently justified RPS/XPS experiment, the analogous scoped write is:

```sh
# CHANGE: exact reviewed queue and bitmap, not an automatically chosen mask.
: "${QUEUE_PATH:?reviewed /sys/class/net/NIC/queues/rx-N/rps_cpus or tx-N/xps_cpus}"
: "${NEW_MASK:?approved hexadecimal CPU bitmap}"
OLD_MASK=$(cat "$QUEUE_PATH")
: "${OLD_MASK:?old mask unreadable}"
(
  set -euo pipefail
  : "${QUEUE_PATH:?verified queue path}" "${NEW_MASK:?approved mask}" "${OLD_MASK:?saved old mask}"
  printf '%s\n' "$NEW_MASK" | sudo tee "$QUEUE_PATH" >/dev/null
  cat "$QUEUE_PATH"
  # ROLLBACK: printf '%s\n' "$OLD_MASK" | sudo tee "$QUEUE_PATH" >/dev/null
)
```

**Expected:** effective placement matches, relevant kernel-path drops/waiting decrease, application outcomes do not regress. **Risk:** starving another queue, NUMA/cache costs, masking the real bottleneck. **Persistence:** often none across restart; approve persistence separately. Zero RPS/XPS can already be correct. Do not apply a CPU bitmap to `xps_rxqs`, which uses queue IDs.

### 6. Service limits or CPU/thread configuration

**Use when:** a verified limit or placement is actually constraining the workload. The report's cgroup membership alone is insufficient evidence of throttling. Nonzero CPU utilization alone is not a reason to raise thread counts.

```sh
# READ ONLY:
: "${UNIT:?actual validator unit}" "${VALIDATOR_PID:?actual PID}"
systemctl show "$UNIT" --property=MainPID,LimitMEMLOCK,LimitNOFILE,CPUAffinity,AllowedCPUs,CPUQuotaPerSecUSec,MemoryMax,TasksMax
cat "/proc/$VALIDATOR_PID/limits"
cat "/proc/$VALIDATOR_PID/cgroup"
```

Obtain effective cgroup constraints and current stage/latency evidence before choosing values. Use [recipe 3](#3-queue-sharing-zero-copy-or-validator-startup-flags) to edit the **actual** reviewed configuration. No generic “unlimited everything,” CPU-quota removal, guessed thread flag or `taskset` on a stale TID is recommended. Service edits may need reload/restart; neither is automatic. **Rollback:** exact previous unit/arguments. **Accept:** constraint was relieved and measured critical-path performance improved without other workloads/leader performance regressing.

### 7. Kernel UDP socket-buffer pressure

**Use when:** fresh `RcvbufErrors` are attributable to an actual validator **kernel UDP socket**, with receive-buffer/consumer evidence. These are namespace-wide counters; the script alone does not establish that attribution. This recipe does not tune AF_XDP rings.

```sh
# READ ONLY, visibility depends on privileges/tools:
ss -u -a -n -m -p
sysctl net.core.rmem_max net.core.rmem_default
```

An application may need to request a larger socket buffer through its supported configuration. Increasing `rmem_max` only raises a ceiling; it does not enlarge existing sockets. Linux's reported SO_RCVBUF/skmem accounting includes overhead, so raw values need their documented interpretation. [Socket buffer semantics](https://man7.org/linux/man-pages/man7/socket.7.html)

```sh
# CHANGE: a justified ceiling only, after application behavior has been verified.
: "${NEW_RMEM_MAX:?approved byte ceiling}"
OLD_RMEM_MAX=$(sysctl -n net.core.rmem_max)
: "${OLD_RMEM_MAX:?old ceiling unreadable}"
(
  set -euo pipefail
  : "${NEW_RMEM_MAX:?approved ceiling}" "${OLD_RMEM_MAX:?saved old ceiling}"
  sudo sysctl -w "net.core.rmem_max=$NEW_RMEM_MAX"
  # READ BACK: confirm both the ceiling AND the intended application's actual buffer.
  sysctl net.core.rmem_max
  ss -u -a -n -m -p
  # ROLLBACK: sudo sysctl -w "net.core.rmem_max=$OLD_RMEM_MAX"
)
```

**Expected:** only after the application uses the intended buffer, attributable drops decrease under matched load. **Tradeoffs:** memory usage and queueing delay; a slow consumer remains slow. **Persistence:** this command is transient. Restoring the ceiling does not shrink buffers already requested by applications; rollback must also restore any changed application setting through its approved lifecycle. [Kernel network sysctls](https://docs.kernel.org/admin-guide/sysctl/net.html)

### 8. Memory, storage or time-related symptoms

Use extra **read-only** checks to identify the actual resource before proposing a change. These are manual additions, not tests already performed by the script. Use only installed tools:

```sh
# READ ONLY:
free -h
swapon --show
cat /proc/pressure/memory
cat /proc/pressure/io
lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS
# For an actual existing validator data directory:
: "${DATA_PATH:?verified ledger/accounts directory}"
findmnt --target "$DATA_PATH"
df -h -- "$DATA_PATH"
df -i -- "$DATA_PATH"
timedatectl show --property=NTPSynchronized,NTP
# If chrony is the existing time service: chronyc tracking
```

Old `lsblk` versions may require `MOUNTPOINT` instead of `MOUNTPOINTS`. PSI or time-service commands may be unavailable. Clock synchronization status alone is not an offset/jitter qualification.

For persistent swap/reclaim/OOM: identify the responsible workload, effective memory limits and real capacity requirement. For storage: map the device first, inspect existing health/error evidence, and distinguish snapshots/backups from steady validation. A provider/device fault or insufficient RAM has no universal shell tuning fix. Do not run a stress test, clear caches, delete ledger data, disable swap, allocate huge pages or change filesystem/scheduler/readahead settings just to improve an audit number.

**Improvement action:** a specifically identified capacity/workload/policy correction, with its own exact command and rollback after that cause is known. Recheck memory/IO pressure, faults, relevant device latency and actual validator delay in matched windows. Disk replacement and cleanup are separate operational procedures, not automatic “performance commands.”

## Check whether a change actually helped

1. **Baseline:** verify target selection and collect at least one representative steady-state window. Record actual client/kernel/driver, traffic/load, active validator role and existing outcome metrics. Exclude startup/catch-up from steady-state comparisons.
2. **Predeclare success:** state the intended setting, mechanism, meaningful benefit and unacceptable regressions. Do this before viewing the after result.
3. **Change one variable:** only the approved action. A startup flag affecting both RX and TX is a combined experiment; do not call it RX-only.
4. **Read back:** use the recipe's effective-value command. A successful write is not proof the application uses it.
5. **Observe the mechanism:** current-session bind/allocation/traffic evidence for XDP, attributable socket drops for kernel buffers, effective CPU placement for affinity, etc.
6. **Collect after:** equal duration/sampling/selection and comparable traffic/leader/load context. Repeat matched windows where practical.
7. **Judge outcomes and rollback:** host improvement is useful only if actual validator delay/participation/leader results remain acceptable. Missing outcome evidence means performance benefit is **INCONCLUSIVE**.

```sh
# READ ONLY collection. Choose real selection values; these files must be new.
bash solana-xdp-check.sh --pid "$VALIDATOR_PID" --interface "$AUDIT_IFACE" --seconds 300 --output ./before.txt
# ...one separately approved change and its read-back...
bash solana-xdp-check.sh --pid "$VALIDATOR_PID" --interface "$AUDIT_IFACE" --seconds 300 --output ./after.txt

# Compare selected observations, retaining both complete original reports.
grep -E 'Requested XDP|file-permitted|nic_.*(dropped|errors)|cpu_work|psi_|disk_.*await|Execution:|Coverage:' ./before.txt
grep -E 'Requested XDP|file-permitted|nic_.*(dropped|errors)|cpu_work|psi_|disk_.*await|Execution:|Coverage:' ./after.txt
```

If using `--service` or `--log-file`, include the same options in both collections. Use `AUDIT_IFACE` consistently even when a change targets only one member named by `NIC`. After a separately approved restart, select the new actual PID; do not reuse a stale one. Re-baseline if metric semantics/build/protocol changed. This two-report workflow uses no extra script and no RPC. It cannot invent slot lag from host counters. Existing local telemetry may supply validator outcomes; any reference data must have compatible time, commitment and fork context.

| Comparison item | Before | After | How to interpret |
|---|---|---|---|
| Effective setting | | | Did the intended configuration take effect? |
| Actual mechanism | | | Did the relevant packet/socket/worker path operate? |
| Load and leader/context exposure | | | Comparable enough to attribute a difference? |
| Relevant errors/drops, same scope | | | New rates lower at comparable traffic, without hiding loss in another layer? |
| CPU/PSI/memory/IO | | | Bottleneck reduced, rather than merely shifted? |
| Valid/invalid intervals and duration | | | Sufficient comparable coverage? |
| Actual validator delay/participation/leader outcomes | | | Improved or at least within predeclared limits? |
| Decision | | | Keep / rollback / inconclusive |

For numbers with identical meaning, absolute change is `after - before`; relative change is `100*(after-before)/before`. If before is zero, percentage change is undefined—report the absolute value. No p99 can be computed from these averages. A single 60-second window is weak evidence for rare events. More valid samples do not guarantee independence; repeating at matched load helps separate an effect from ordinary variability.

## Troubleshooting, scope and tests

| Symptom | Meaning / next step |
|---|---|
| “all four capabilities present” but actual RX UNKNOWN | File prerequisite passed; need current-session per-port/bind/traffic evidence |
| Missing file caps although XDP appears active | Inspect launch/ambient/bounding policy and adoption; do not change privileges from that observation alone |
| `CapEff=0`, `NoNewPrivs=1` | May be intentional runtime lockdown; distinguish pre-exec policy from post-setup state |
| `off_fixed` | Unsupported receive-steering prerequisite; an ethtool toggle cannot make it supported |
| `no_operations_reset_or_identity` on disk await | No completed operations can be normal; also check device identity/reset evidence |
| `disk_identity_missing_or_reset` | Disk identity, including diskseq, could not be kept stable; do not use those rates as measurements |
| PID/thread/device reset or change | Split sessions; do not interpret a reset as negative activity or improvement |
| Read denied / tool missing / output truncated | Coverage issue; investigate the exact command, permission and support. Changing runtime settings will not fix a diagnostic schema gap |
| Existing output file | Choose a new filename; it will not be overwritten |
| Root output directory refused | Use the normal operator or an existing approved protected root-owned working directory; don't weaken directory permissions |
| Complete run with UNKNOWNs | Normal for facts this observational method cannot prove. No need to “tune until all green” |
| Report incomplete | Read `Execution`/`Coverage`; preserve evidence and fix the particular resource/read issue before rerunning |

### Remove an audit report

The audit requires no uninstall, capability removal or XDP reset. To remove only a saved report, delete its exact filename after you no longer need the evidence:

```sh
# FILE CLEANUP ONLY: exact report you intend to discard; no wildcard.
rm -- ./before.txt
```

`clear` clears the terminal display; it does not remove saved files or undo any separately applied tuning.

### Validation

The present script has 16 embedded tests. Independent single-file review added 19 cases: 18 passed and one POSIX mode/symlink case was skipped on Windows. Bash syntax and embedded Python syntax were checked. These are synthetic/local development checks, **not a live Linux/NIC acceptance test**. The report-location default was checked separately. All README shell examples were syntax-checked with Bash, and the README was checked against the delivered script. Manual change commands have not been run on your server.

```sh
bash -n solana-xdp-check.sh
bash solana-xdp-check.sh --self-test
```

Bounds include 16 interfaces/layers, 512 thread entries, 256 detailed queues per interface, 512 utility calls and an 8 MiB text-report allowance with room reserved for finalization. Clipped/unavailable evidence must be treated as limited coverage. Reports include host paths, network/topology and operational details; keep them private and review before sharing. Conservative secret redaction is not a guarantee that arbitrary unlabeled secrets are absent.

Prepared against the accompanying script on 21 October 2026. No actual server report has been supplied here, so this document provides conditional decisions rather than a diagnosis or guessed tuning values.
