from monitor.scanner import get_processes
from detection.rules import get_real_path, is_from_temp, suspicious_relation, is_unattributed
from output.formatter import print_alert, print_network_connections, print_network_alert, write_alert
from monitor.network import get_established_connections
import time

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
                print_alert(process, "Process Running from /tmp")
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
                print_alert(process, reason)
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

def main():
    print(f"Guardian started, scanning every {SCAN_INTERVAL_SECONDS} seconds. Ctrl+C to stop.")
    already_alerted = set()

    while True:
        already_alerted = run_scan(already_alerted)
        time.sleep(SCAN_INTERVAL_SECONDS)
    
   
if __name__ == "__main__":
    main() 