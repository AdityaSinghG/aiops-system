import paramiko
from datetime import datetime


class SSHExecutor:
    """
    Runs remediation commands on a remote server via SSH.
    Used in production/Azure environment by the team.
    """

    def __init__(self, host: str, username: str, password: str = None, key_path: str = None, port: int = 22):
        """
        Args:
            host: IP address or hostname of the target server
            username: SSH username
            password: SSH password (use this OR key_path, not both)
            key_path: Path to private key file e.g. "~/.ssh/id_rsa"
            port: SSH port, default 22
        """
        self.host = host
        self.username = username
        self.password = password
        self.key_path = key_path
        self.port = port
        self.client = None

    def connect(self):
        """Opens the SSH connection to the target server."""
        self.client = paramiko.SSHClient()

        # Automatically accept the server's host key (safe for internal servers)
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if self.key_path:
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                key_filename=self.key_path
            )
        else:
            self.client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password
            )

    def disconnect(self):
        """Closes the SSH connection cleanly."""
        if self.client:
            self.client.close()
            self.client = None

    def execute(self, command: str, timeout: int = 30) -> dict:
        """
        SSHes into the remote server, runs the command, returns structured result.

        Args:
            command: The shell command to run on the remote server
            timeout: Max seconds to wait for the command to finish

        Returns:
            dict with keys: success, stdout, stderr, return_code, command, timestamp
        """
        timestamp = datetime.utcnow().isoformat()

        try:
            self.connect()

            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout)

            # Wait for command to finish and read output
            stdout_output = stdout.read().decode("utf-8").strip()
            stderr_output = stderr.read().decode("utf-8").strip()
            return_code = stdout.channel.recv_exit_status()

            return {
                "success": return_code == 0,
                "stdout": stdout_output,
                "stderr": stderr_output,
                "return_code": return_code,
                "command": command,
                "timestamp": timestamp,
                "executor_type": "ssh",
                "host": self.host
            }

        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "command": command,
                "timestamp": timestamp,
                "executor_type": "ssh",
                "host": self.host
            }

        finally:
            # Always disconnect even if something went wrong
            self.disconnect()