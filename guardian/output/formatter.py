def print_alert(process, reason):
    print(f"\n! SUSPICIOUS PROCESS DETECTED !")
    print(f"    Process : {process.name} (PID {process.id})")
    print(f"    Parent  : PID {process.parent_id}")
    print(f"    Reason  : {reason}")
    print()