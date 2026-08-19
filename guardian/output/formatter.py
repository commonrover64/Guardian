def print_alert(process, reason):
    print(f"\n! SUSPICIOUS PROCESS DETECTED !")
    print(f"    Process : {process.name} (PID {process.id})")
    print(f"    Parent  : PID {process.parent_id}")
    print(f"    Reason  : {reason}")
    print()

def print_network_connections(connections):
    print("\nEstablished Network Connections:")
    print("-" * 75)

    for connection in connections:
        print(
            f"{connection['process_name']:<12} "
            f"(PID {connection['pid']:<6}) "
            f"{connection['local_ip']}:{connection['local_port']} "
            f"-> "
            f"{connection['remote_ip']}:{connection['remote_port']}"
        )

    print("-" * 75)