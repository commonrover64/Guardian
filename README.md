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

When a rule matches, Guardian prints a clear alert and also writes it as a structured JSON record to `alerts.jsonl`, so alerts can be picked up by other tools later, not just read on screen.

## Project structure
```
guardian/
  main.py                entry point
  monitor/
    process.py            the Process data model or Process class
    scanner.py             reads /proc and builds the process list
    network.py             reads established TCP connections and maps them to owning processes
  detection/
    rules.py                the actual detection logic
  output/
    formatter.py             turns a flagged process or connection into a readable alert, and writes JSON alerts to alerts.jsonl
```

## Demo
**Rule 1: Suspicious Execution Path (catches processes running from /tmp)**

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

**Rule 2: Anomalous Parent-Child Execution (catches unusual process spawn pairings)**

to trigger rule 2, temporarily added `"bash": {"sleep"}` to the suspicious parent/child dictionary in `rules.py`, since `sleep` was being launched from a bash shell during testing. Removed it again after confirming the rule fires correctly.
```
! SUSPICIOUS PROCESS DETECTED !
    Process : sleep (PID 113733)
    Parent  : PID 89977
    Reason  : Unusual for "bash" to execute "sleep"
```

**Rule 3: Unattributed Network Connection (catches established connections with no owning process found)**

> Note: this rule hasn't fired on my own machine during testing, since simulating a truly unattributed socket isn't something you can safely fake on a normal system. The detection logic is in place and the other two rules prove the overall architecture works, this one just hasn't had a real trigger yet.

**Structured alert logging**

Every alert, regardless of which rule fires, also gets written to `alerts.jsonl` as a single JSON line, for example:

```json
{"timestamp": "2026-08-20T07:52:38.788804+00:00", "rule": "process_from_tmp", "details": {"process_name": "sleep", "pid": 45154, "parent_pid": 34395, "path": "/tmp/sleep"}}
```

## Known limitations
- needs root to read every process on the system, since some `/proc` entries aren't readable otherwise.
- the suspicious parent/child list is a small example set. real EDR tools maintain much bigger, constantly updated rule sets.
- network visibility is limited to established TCP connections read from `/proc/net/tcp`. doesn't inspect packet contents, UDP traffic, or non TCP protocols.
- this only looks at process metadata and network connection metadata, it doesn't inspect file contents or memory, where a real EDR tool covers a lot more ground.