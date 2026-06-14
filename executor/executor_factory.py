from executor.local_executor import LocalExecutor
from executor.ssh_executor import SSHExecutor


# --- CONFIG ---
# Change this one line to switch between local and SSH execution
# "local"  → runs commands on your Windows laptop (dev/testing)
# "ssh"    → runs commands on a remote server (production/team)

EXECUTOR_MODE = "local"

# SSH config — only used when EXECUTOR_MODE = "ssh"
# Your team fills these in when they deploy to Azure
SSH_CONFIG = {
    "host": "192.168.1.100",       # IP of the target server
    "username": "azureuser",        # SSH username
    "password": "your-password",    # SSH password OR use key_path below
    "key_path": None,               # e.g. "~/.ssh/id_rsa" — set this if using key auth
    "port": 22
}


def get_executor():
    """
    Returns the right executor based on EXECUTOR_MODE.
    The agent calls this and never needs to know which one it gets.
    """
    if EXECUTOR_MODE == "local":
        return LocalExecutor()

    elif EXECUTOR_MODE == "ssh":
        return SSHExecutor(
            host=SSH_CONFIG["host"],
            username=SSH_CONFIG["username"],
            password=SSH_CONFIG["password"],
            key_path=SSH_CONFIG["key_path"],
            port=SSH_CONFIG["port"]
        )

    else:
        raise ValueError(f"Unknown executor mode: '{EXECUTOR_MODE}'. Use 'local' or 'ssh'.")