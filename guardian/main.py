from monitor.scanner import get_processes
from detection.rules import get_real_path, is_from_temp, suspicious_relation
from output.formatter import print_alert

def main():
    print(f"Getting all Processes...\n")

    processes = get_processes()

    for process in processes:
        path = get_real_path(process)
        
        if is_from_temp(path):
            print_alert(process, "Process Running from /tmp")

        if suspicious_relation(process):
            print_alert(process, f"Unusual for the {process.parent_name} to execute {process.name}")



    
if __name__ == "__main__":
    main()