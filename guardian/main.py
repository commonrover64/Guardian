from dotenv import load_dotenv
load_dotenv()
from monitor.scanner import get_processes
from detection.rules import get_real_path, is_from_temp, suspicious_relation, is_unattributed, matches_lolbin_chain
from output.formatter import print_alert,print_network_alert, write_alert
from monitor.network import get_established_connections
import time, queue, threading
from monitor.ebpf import EbpfMonitor
from detection.lineage import LineageTracker

SCAN_INTERVAL_SECONDS = 5

def run_scan(already_alerted):
    
    processes = get_processes()
    current_pids = {process.id for process in processes}

    # drop tracked alerts for pids that no longer exist, so a reused pid doing something suspicious again isn't silently ignored
    already_alerted = {key for key in already_alerted if key[0] in current_pids}

    for process in processes:
        path = get_real_path(process)
        
        if is_from_temp(path):
            key = (process.id, "Process_from_tmp")
            if key not in already_alerted:
                print_alert(process.name, process.id, process.parent_id, "Process Running from /tmp")

                write_alert("process_from_tmp", {
                    "process_name": process.name,
                    "pid": process.id,
                    "parent_pid": process.parent_id,
                    "path": path
                })
                already_alerted.add(key)

        if suspicious_relation(process):
            key = (process.id, "suspicious_parent_child")
            if key not in already_alerted:
                reason = f"Unusual for \"{process.parent_name}\" to execute \"{process.name}\""
                print_alert(process.name, process.id, process.parent_id, reason)
                write_alert("suspicious_parent_child", {
                    "process_name": process.name,
                    "pid": process.id,
                    "parent_name": process.parent_name,
                    "parent_pid": process.parent_id
                })
                already_alerted.add(key)

    connections = get_established_connections(processes)
    for connection in connections:
        if is_unattributed(connection):
            print_network_alert(connection, "No owning process found for this connection's socket")


            write_alert("unattributed_connection", {
                "local_ip": connection["local_ip"],
                "local_port": connection["local_port"],
                "remote_ip": connection["remote_ip"],
                "remote_port": connection["remote_port"]
            })
    return already_alerted

def check_immediate_alerts(event, lineage, already_alerted):
    # runs the two eBPF-dependent rules right when the event arrives, not on the 5s scan
    if event["type"] == "exec":
        technique_id = matches_lolbin_chain(event["pid"], event["comm"], lineage)
        if technique_id:
            key = (event["pid"], "lolbin_chain")
            if key not in already_alerted:
                parent_id = lineage.processes.get(event["pid"], {}).get("ppid")
                reason = f"Process chain matches known LOLBin pattern ({technique_id})"
                print_alert(event["comm"], event["pid"], parent_id, reason)
                write_alert("lolbin_chain", {
                    "process_name": event["comm"],
                    "pid": event["pid"],
                    "chain": lineage.get_chain(event["pid"]),
                    "technique_id": technique_id
                })
                already_alerted.add(key)

    elif event["type"] == "connect":
        if lineage.is_short_lived_with_connection(event["pid"]):
            key = (event["pid"], "short_lived_with_connection")
            if key not in already_alerted:
                comm = lineage.processes.get(event["pid"], {}).get("comm")
                parent_id = lineage.processes.get(event["pid"], {}).get("ppid")
                print_alert(comm, event["pid"], parent_id, "Short-lived process made a network connection")
                write_alert("short_lived_with_connection", {
                    "process_name": comm,
                    "pid": event["pid"]
                })
                already_alerted.add(key)

    return already_alerted

def main():
    print(f"Guardian started, scanning every {SCAN_INTERVAL_SECONDS} seconds. Ctrl+C to stop.")
    already_alerted = set()

    shared_queue = queue.Queue()
    lineage = LineageTracker()
    ebpf = EbpfMonitor(shared_queue)
    ebpf_thread = threading.Thread(target=ebpf.run, daemon=True)
    ebpf_thread.start()

    try:
        while True:
            # drain queue here later once lineage.py exists to consiume these events
            while not shared_queue.empty():
                event = shared_queue.get()
                lineage.handle_event(event)
                already_alerted = check_immediate_alerts(event, lineage, already_alerted)
            already_alerted = run_scan(already_alerted)

            time.sleep(SCAN_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("Stopping Guardian...")
        ebpf.stop()
        ebpf_thread.join()
   
if __name__ == "__main__":
    main() 