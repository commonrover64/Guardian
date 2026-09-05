# Guardian
A process monitoring tool for Linux that flags suspicious process behavior. Basically a small hand built taste of what EDR (Endpoint Detection and Response) tools do under the hood.

## How it works
Guardian reads live process info straight from `/proc` on Linux (no external libraries needed for that part) and runs each process through three detection rules (you can add your own rules):

**Rule 1: Running from /tmp**
checks where a process's actual executable is. if it's running out of `/tmp`, that's flagged. legit software usually lives in predictable place like `/usr/bin`. Malware often gets dropped into world writable folders like `/tmp` instead.

**Rule 2: Suspicious parent/child pairing**
this tracks which process started which. some parent/child pairings can be a little odd in a normal setup, like a firefox process spawning a shell. this isnt proof of malicious activity but they're worth flagging.

**Rule 3: Unattributed network connections**
Guardian reads established TCP connections from `/proc/net/tcp` and tries to match each one back to the process that owns it, by mapping socket inodes to process file descriptors. if a connection cant be matched to any process, it gets flagged since that can be a sign of something hiding its network activity.

**Rule 4: LOLBin chain detection** tracks real-time process lineage via eBPF (using bpftrace), not just a single parent/child pair like Rule 2, but the actual exec chain leading up to a process. Certain chains, like `bash` spawning `curl`, or `python3` spawning `bash`, are common living-off-the-land patterns attackers use to blend in with legitimate system activity. Matches are tagged with a [MITRE ATT&CK technique ID](https://attack.mitre.org/techniques/enterprise/).

**Rule 5: Short-lived process with a network connection** catches processes that make an outbound connection and exit quickly, often too fast for `/proc` polling alone to ever see them. This is only possible because of the eBPF layer running alongside the polling scanner, catching exec and exit events the instant they happen instead of on a fixed interval.

When a rule matches, Guardian prints a clear alert and also writes it as a structured JSON record to `alerts.jsonl`, so alerts can be picked up by other tools later, not just read on screen.

## Project structure
```
guardian/
  main.py                entry point
  monitor/
    process.py            the Process data model or Process class
    scanner.py             reads /proc and builds the process list
    network.py             reads established TCP connections and maps them to owning processes
    ebpf.py                runs bpftrace probes for real-time exec/connect/exit events
  detection/
    rules.py                the detection logic, including LOLBin chain matching
    lineage.py               tracks process ancestry from eBPF events, prunes on exit
  output/
    formatter.py             turns a flagged process or connection into a readable alert, writes JSON alerts to alerts.jsonl, and forwards alerts to Elasticsearch when enabled
    elastic_client.py        optional Elasticsearch client, controlled via ELASTIC_ENABLED env var
```

## Demo
**Rule 1 DEMO: Suspicious Execution Path (catches processes running from /tmp)**

For triggering rule 1, i copied a real binary into `/tmp` and ran it from there so that its actual executable path lives in `/tmp`:

```
cp /bin/sleep /tmp/sleep
/tmp/sleep 100
```

```
! SUSPICIOUS PROCESS DETECTED !
    Process : sleep (PID 113733)
    Parent  : PID 89977 
    Reason  : Process Running from /tmp
```

**Rule 2 DEMO: Anomalous Parent-Child Execution (catches unusual process spawn pairings)**

to trigger rule 2, temporarily added `"bash": {"sleep"}` to the suspicious parent/child dictionary in `rules.py`, since `sleep` was being launched from a bash shell during testing. Removed it again after confirming the rule fires correctly.
```
! SUSPICIOUS PROCESS DETECTED !
    Process : sleep (PID 113733)
    Parent  : PID 89977
    Reason  : Unusual for "bash" to execute "sleep"
```

**Rule 3 DEMO: Unattributed Network Connection (catches established connections with no owning process found)**

> Note: this rule hasn't fired on my own machine during testing, since simulating a truly unattributed socket isn't something you can safely fake on a normal system. The detection logic is in place and the other two rules prove the overall architecture works, this one just hasn't had a real trigger yet.

**Rule 4 DEMO: LOLBin Chain Detection (catches known suspicious exec chains)**

```
bash -c "curl example.com"
```
```
! SUSPICIOUS PROCESS DETECTED !
Process : curl (PID 77849)
Parent : PID 7343
Reason : Process chain matches known LOLBin pattern (T1105)
```

**Optional: Elasticsearch integration**

Set `ELASTIC_ENABLED=true` along with `ELASTIC_HOST`, `ELASTIC_INDEX`, and `ELASTIC_API_KEY` in a `.env` file to also send every alert to an Elasticsearch index, for building dashboards in Kibana on top of Guardian's own alert data. Disabled by default, local JSON logging always works regardless.

## Structured alert logging

Every alert, regardless of which rule fires, also gets written to `alerts.jsonl` as a single JSON line, for example:

```json
{"timestamp": "2026-08-20T07:52:38.788804+00:00", "rule": "process_from_tmp", "details": {"process_name": "sleep", "pid": 45154, "parent_pid": 34395, "path": "/tmp/sleep"}}
```

## Known limitations
- needs root to read every process on the system, since some `/proc` entries aren't readable otherwise.
- the suspicious parent/child list is a small example set. real EDR tools maintain much bigger, constantly updated rule sets.
- network visibility is limited to established TCP connections read from `/proc/net/tcp`. doesn't inspect packet contents, UDP traffic, or non TCP protocols.
- this only looks at process metadata and network connection metadata, it doesn't inspect file contents or memory, where a real EDR tool covers a lot more ground.
- LOLBin chain patterns are a small example set, same caveat as the parent/child list, real detections need much broader, regularly updated rule sets.
- eBPF-based detection requires bpftrace and root privileges, same as the rest of Guardian, but is an additional system dependency beyond just Python.