def print_alert(process, reason):
    print(f"\n! SUSPICIOUS PROCESS DETECTED !")
    print(f"    Process : {process.name} (PID {process.pid})")
    print(f"    Parent  : PID {process.ppid}")
    print(f"    Reason  : {reason}")
    print()