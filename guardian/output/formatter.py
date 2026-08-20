import json
from datetime import datetime, timezone

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

def print_network_alert(connection, reason):
    print(f"\n! SUSPICIOUS NETWORK CONNECTION DETECTED !")
    print(f"    Process      : {connection['process_name']} (PID {connection['pid']})")
    print(f"    Local        : {connection['local_ip']}:{connection['local_port']}")
    print(f"    Remote       : {connection['remote_ip']}:{connection['remote_port']}")
    print(f"    Reason       : {reason}")
    print()

def write_alert(rule_name, details, filepath = "alerts.jsonl"):
    alert = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": rule_name,
        "details": details,
    }
    with open(filepath, "a") as file:
        file.write(json.dumps(alert) + "\n")