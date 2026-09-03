import subprocess, threading, time

# bpftrace script, one probe per event, piped output parsed by handle_line
BPFTRACE_SCRIPT = """
tracepoint:syscalls:sys_enter_execve
{
    printf("EXEC|%d|%d|%s\\n", pid, curtask->real_parent->tgid, comm);
}

tracepoint:syscalls:sys_enter_connect
{
    printf("CONNECT|%d\\n", pid);
}

tracepoint:sched:sched_process_exit
{
    printf("EXIT|%d\\n", pid);
}
"""

class EbpfMonitor:
    def __init__(self, shared_queue):
        self.shared_queue = shared_queue
        self.stop_flag = threading.Event()
        self.process = None

    def run(self):         # runs bpftrace as a subprocess, reads its stdout line by line
        self.process = subprocess.Popen(
            ["bpftrace", "-e", BPFTRACE_SCRIPT],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )

        for line in self.process.stdout:
            if self.stop_flag.is_set():
                break

            self.handle_line(line.strip())

    def handle_line(self, line):          # parses one bpftrace output line and pushes a normalized event to the queue
        parts = line.split("|") 
        event_type = parts[0]

        if event_type == "EXEC" and len(parts) == 4:
            self.shared_queue.put({
                "type": "exec",
                "pid": int(parts[1]),
                "ppid": int(parts[2]),
                "comm": parts[3],
                "ts": time.time(),
            }) 
        elif event_type == "connect" and len(parts) == 2:
            self.shared_queue.put({
                "type": "connect",
                "pid": int(parts[1]),
                "ts": time.time(),
            })
        elif event_type == "EXIT" and len(parts) == 2:
            self.shared_queue.put({
                "type": "exit",
                "pid": int(parts[1]),
                "ts": time.time(),
            })

    def stop(self):        # terminating the subprocess closes stdout, which ends the run() loop
        self.stop_flag.set()
        if self.process:
            self.process.terminate()
