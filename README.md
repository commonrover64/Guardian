# Guardian
A process monitoring tool for Linux that flags suspicious process behavior. Basically a small hand built taste of what EDR (Endpoint Detection and Response) tools do under the hood.
 
## How it works
Guardian reads live process info straight from `/proc` on Linux (no external libraries needed for that part) and runs each process through a couple of detection rules (you can add your own rules):
 
**Rule 1: Running from /tmp**
checks where a process's actual executable is. if it's running out of `/tmp`, that's flagged. legit software usually lives in predictable place like `/usr/bin`. Malware often gets dropped into world writable folders like `/tmp` instead.
 
**Rule 2: Suspicious parent/child pairing**
this tracks which process started which. some parent/child can be little odd in a normal setup, like firefox process spawning a shell. this isnt a proof of malicious activity but they're worth flagging. 

When a rule matches, Guardian prints a clear alert with the process name, PID(Process Id), parent PID, and the reason it got flagged.
 
## Project structure
```
guardian/
  main.py              entry point
  monitor/
    process.py          the Process data model or Process class
    scanner.py           reads /proc and builds the process list
  detection/
    rules.py              the actual detection logic
  output/
    formatter.py          turns a flagged process into a readable alert
```
 
## Demo
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
 
and to trigger rule 2, temporarily added `"bash": {"sleep"}` to the suspicious parent/child dictionary in `rules.py`, since `sleep` was being launched from a bash shell during testing. Removed it again after confirming the rule fires correctly.
```
! SUSPICIOUS PROCESS DETECTED !
    Process : sleep (PID 113733)
    Parent  : PID 89977
    Reason  : Unusual for "bash" to execute "sleep"
```

## Known limitations 
- needs root to read every process on the systemsince some `/proc` entries aren't readable otherwise.
- the suspicius parent/child list is a small example set. real EDR tools maintain much bigger, constantly updated rule sets.
- this only looks at process metadata, it doesn't inspect file contents, network activity, or memory where a real EDR tool covers a lot more stuffs.
- no persistence or logging to a file yet, alerts just print to the terminal for now.