from monitor.scanner import get_processes

def main():
    print(f"Getting all Processes...\n")

    processes = get_processes()

    for process in processes:
        print(f"Process ID: {process.pid} - Process ParentId: {process.ppid} - Process Name: {process.name}\n")

if __name__ == "__main__":
    main()