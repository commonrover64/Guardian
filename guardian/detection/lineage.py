import time

class LineageTracker:
    # tracks pid -> parent pid + exec time, pruned when a process exits

    def __init__(self, short_lived_threshold_seconds=2):
        self.processes = {}
        self.short_lived_threshold_seconds = short_lived_threshold_seconds

    def handle_event(self, event):
        if event["type"] == "exec":
            self.processes[event["pid"]] = {
                "ppid": event["ppid"],
                "comm": event["comm"],
                "exec_time": event["ts"],
                "connected": False
            }
        elif event["type"] == "connect":
            if event["pid"] in self.processes:
                self.processes[event["pid"]]["connected"] = True
        elif event["type"] == "exit":
            self.processes.pop(event["pid"], None)

    def get_chain(self, pid):
        # walks up from pid to root, returns list of comm names, closest ancestor first
        chain = []
        current = self.processes.get(pid)
        seen = set()

        while current and current["ppid"] not in seen:
            chain.append(current["comm"])
            seen.add(current["ppid"])
            current = self.processes.get(current["ppid"])
        return chain

    def is_short_lived_with_connection(self, pid):
        # true if the process connected out and is still under the threshold age
        process = self.processes.get(pid)
        if not process or not process["connected"]:
            return False

        return (time.time() - process["exec_time"]) < self.short_lived_threshold_seconds