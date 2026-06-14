import subprocess
import platform
from datetime import datetime


class LocalExecutor:
    """
    Runs remediation commands directly on the local machine via subprocess.
    Used for local dev/testing on your Windows laptop.
    """

    def __init__(self):
        self.os_type = platform.system()  # 'Windows' or 'Linux'

    def execute(self, command: str, timeout: int = 30) -> dict:
        """
        Runs a shell command locally and returns structured result.

        Args:
            command: The shell command to run
            timeout: Max seconds to wait before killing the command

        Returns:
            dict with keys: success, stdout, stderr, return_code, command, timestamp
        """
        timestamp = datetime.utcnow().isoformat()

        # On Windows, run through cmd.exe so normal Windows commands work
        if self.os_type == "Windows":
            shell_cmd = ["cmd.exe", "/c", command]
        else:
            shell_cmd = ["bash", "-c", command]

        try:
            result = subprocess.run(
                shell_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "return_code": result.returncode,
                "command": command,
                "timestamp": timestamp,
                "executor_type": "local"
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "return_code": -1,
                "command": command,
                "timestamp": timestamp,
                "executor_type": "local"
            }

        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "command": command,
                "timestamp": timestamp,
                "executor_type": "local"
            }