from monitor.scanner import get_processes
from detection.rules import get_real_path, is_from_temp, suspicious_relation, is_unattributed
from output.formatter import print_alert, print_network_connections, print_network_alert, write_alert
from monitor.network import get_established_connections

def main():
    print(f"Getting all Processes...\n")

    processes = get_processes()

    for process in processes:
        path = get_real_path(process)
        
        if is_from_temp(path):
            print_alert(process, "Process Running from /tmp")

            write_alert("process_from_tmp", {
                "process_name": process.name,
                "pid": process.id,
                "parent_pid": process.parent_id,
                "path": path
            })

        if suspicious_relation(process):
            reason = f"Unusual for \"{process.parent_name}\" to execute \"{process.name}\""
            print_alert(process, reason)
            write_alert("suspicious_parent_child", {
                "process_name": process.name,
                "pid": process.id,
                "parent_name": process.parent_name,
                "parent_pid": process.parent_id
            })

    print(f"\nGetting Established Network connections...\n")
    connections = get_established_connections(processes)
    print_network_connections(connections)

    for connection in connections:
        if is_unattributed(connection):
            print_network_alert(connection, "No owning process found for this connection's socket")
            write_alert("unattributed_connection", {
                "local_ip": connection["local_ip"],
                "local_port": connection["local_port"],
                "remote_ip": connection["remote_ip"],
                "remote_port": connection["remote_port"]
            })
   
if __name__ == "__main__":
    main() 