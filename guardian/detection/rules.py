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