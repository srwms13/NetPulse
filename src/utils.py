import subprocess
import platform

def run_ping(host: str, count: int = 4):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    command = ["ping", param, str(count), host]

    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = proc.communicate()

        if proc.returncode != 0 and stderr:
            return stderr, proc.returncode

        return stdout, proc.returncode

    except Exception as e:
        return f"Ping Error: {e}", 1
