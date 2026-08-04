import os

# 1st rule
def get_real_path(process):
    process_real_path = "not found yet"
    try:
        process_real_path = os.readlink(f"/proc/{process.id}/exe")
    except FileNotFoundError:
        print("error finding real path")

    return process_real_path

def is_from_temp(path):
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
