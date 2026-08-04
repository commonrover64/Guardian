import os

def get_real_path(process):
    process_real_path = "not found yet"
    try:
        process_real_path = os.readlink(f"/proc/{process.pid}/exe")
    except FileNotFoundError:
        print("error finding real path")

    return process_real_path

def is_from_temp(path):
    return path == "/tmp" or path.startswith("/tmp/")