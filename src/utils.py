import subprocess
import platform

def run_ping(host: str):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '4', host]

    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0 and stderr:
            return stderr, process.returncode

        return stdout, process.returncode

    except Exception as e:
        return f"Ping error: {e}", 1
