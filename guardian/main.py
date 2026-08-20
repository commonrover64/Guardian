from monitor.scanner import get_processes
from detection.rules import get_real_path, is_from_temp, suspicious_relation, is_unattributed
from output.formatter import print_alert, print_network_connections, print_network_alert
from monitor.network import get_established_connections

def main():
    print(f"Getting all Processes...\n")

    processes = get_processes()

    for process in processes:
        path = get_real_path(process)
        
        if is_from_temp(path):
            print_alert(process, "Process Running from /tmp")

        if suspicious_relation(process):
            print_alert(process, f"Unusual for \"{process.parent_name}\" to execute \"{process.name}\"")

    print(f"\nGetting Established Network connections...\n")
    connections = get_established_connections(processes)
    print_network_connections(connections)

    for connection in connections:
        if is_unattributed(connection):
            print_network_alert(connection, "No owning process found for this connection's socket")
   
if __name__ == "__main__":
    main() 