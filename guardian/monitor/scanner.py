import os
from monitor.process import Process

def get_processes():
    processes = []
    proc_entries = os.listdir("/proc")

    for item in proc_entries:
        if item.isdigit():
            name = "not_a_process"
            pid = int(item)
            ppid = None

            try:
                # using with automatically closes the file when we are done. prevents mem leak
                with open(f"/proc/{item}/status", 'r', encoding='utf-8') as file:
                    for line in file:

                        # Split each line by the colon into key and value
                        if ':' not in line:
                            continue

                        key, value = line.split(':', 1)
                        # clean extra whitespace and newlines
                        key = key.strip()
                        
                        if key == 'Name':
                            name = value.strip()

                        if key == 'PPid':
                            ppid = value.strip()

                        if name and ppid:
                            break # no point reading rest of the file
                                
            except FileNotFoundError:
                continue

            # print(f"name: {name} & pid: {pid}")

            process = Process(pid, ppid,name)
            processes.append(process)


    return processes
