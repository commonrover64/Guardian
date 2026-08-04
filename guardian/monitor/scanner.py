import os
from monitor.process import Process

def get_processes():
    processes = []
    pid_to_name = {} # processid: name pair
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
                        value = value.strip()
                        
                        if key == 'Name':
                            name = value

                        if key == 'PPid':
                            ppid = int(value)

                        if name and ppid:
                            break # no point reading rest of the file
                                
            except FileNotFoundError:
                continue

            process = Process(pid, name, ppid, None)
            processes.append(process)
            pid_to_name[pid] = name

    # fill in all parents name
    for process in processes:
        process.parent_name = pid_to_name.get(process.parent_id)


    return processes