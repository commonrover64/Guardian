import os

def hex_to_ip(hex_str):
    # split "031DA8C0" into ["03", "1D", "A8", "C0"]
    byte_pairs = [hex_str[i:i+2] for i in range(0, 8, 2)]

    # reverse the order and convert each pair fromhex to dec. C0 becmes 192 A8 becomes 168 and so on
    decimal_bytes = [str(int(b, 16)) for b in reversed(byte_pairs)]

    return ".".join(decimal_bytes)  # returns something like 192.168.29.3

def hex_to_port(hex_str):
    return int(hex_str, 16)

def find_pid_by_inode(inode):
    target = f"socket:[{inode}]"

    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        fd_path = f"/proc/{pid}/fd"

        try:
            for fd in os.listdir(fd_path):
                link = os.readlink(f"{fd_path}/{fd}")
                if link == target:
                    return int(pid)
        except (PermissionError, FileNotFoundError):
            continue    # process may disappear or deny access when scanning 

    return None

def get_established_connections(processes):
    connections = []

    # map Pid process so we can quickly see the owner of a socket
    process_by_id = {process.id: process for process in processes}
    
    with open("/proc/net/tcp", "r") as file:
        lines = file.readlines()[1:]    # skips the header row

    for line in lines:
        fields = line.split()

        local_address = fields[1]   # eg: 031DA8C0:BD5C
        remote_address = fields[2]
        state = fields[3]
        inode = fields[9]

        if state != "01":       # only check established conn
            continue

        local_ip, local_port = local_address.split(":")
        remote_ip, remote_port = remote_address.split(":")

        connection_inode = int(inode)
        pid = find_pid_by_inode(connection_inode)

        process = process_by_id.get(pid)

        connections.append({
            "local_ip": hex_to_ip(local_ip),
            "local_port": hex_to_port(local_port),
            "remote_ip": hex_to_ip(remote_ip),
            "remote_port": hex_to_port(remote_port),
            "inode": int(inode),
            "pid": pid,
            "process_name": process.name if process else "Unknown"
        })
    return connections