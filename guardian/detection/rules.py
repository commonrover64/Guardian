import os

# 1st rule
def get_real_path(process):
    try:
        return os.readlink(f"/proc/{process.id}/exe")
    except FileNotFoundError:
        # print(f"Executable for process {process.id} not found")
        return None
    
def is_from_temp(path):
    if path == None: 
        return False
    return path == "/tmp" or path.startswith("/tmp/")

# 2nd rule
# these parent/child pairings are just example and does not always mean the activity is malicious
suspicious_parent_child_relation = {
    "nginx": {"bash", "sh", "zsh", "dash"},
    "apache2": {"bash", "sh"},
    "httpd": {"bash", "sh"},
    "php-fpm": {"bash", "sh"},
    "java": {"bash", "sh"},
    "firefox": {"bash", "sh"},
    "chrome": {"bash", "sh"},
    "libreoffice": {"bash", "sh"},
}

def suspicious_relation(process):
    parent = process.parent_name
    child = process.name

    if parent is None or child is None:
        return False

    return child in suspicious_parent_child_relation.get(parent, set()) # returns all the childs for this parent in set and then checks if the current child is one of them

# 3rd rule. flag network connections with no owning process found via inode lookup
def is_unattributed(connection):
    return connection["pid"] is None

LOLBIN_CHAINS = [
    (["python3", "bash"], "T1059.004"),
    (["bash", "nc"], "T1059.004"),
    (["bash", "curl"], "T1105"),
    (["bash", "wget"], "T1105"),
    (["cron", "bash"], "T1053.003"),
    (["sshd", "bash"], "T1059.004"),
    (["winword.exe", "powershell.exe"], "T1059.001"),
    (["excel.exe", "powershell.exe"], "T1059.001"),
    (["powershell.exe", "certutil.exe"], "T1105"),
]

def matches_lolbin_chain(process, lineage):
    chain = lineage.get_chain(process.id)
    full_chain = [process.name] + chain

    for pattern, technique_id in LOLBIN_CHAINS:
        if pattern == full_chain[:len(pattern)]:
            return technique_id

    return None

def is_short_lived_attacker(process, lineage):
    return lineage.is_short_lived_with_connection(process.id)