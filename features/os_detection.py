# features/os_detection.py

import platform
import subprocess
import re

def run_os_detection(target: str) -> dict:
    try:
        # Send 1 ping and get TTL from the response
        ping_count = 1
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, str(ping_count), target]
        output = subprocess.check_output(command, universal_newlines=True)

        # Extract TTL value
        ttl_match = re.search(r"ttl[=|:](\d+)", output, re.IGNORECASE)
        if not ttl_match:
            return {
                "status": "error",
                "message": "Could not determine TTL from ping response."
            }

        ttl = int(ttl_match.group(1))

        # Infer OS from TTL
        if ttl >= 128:
            os_guess = "Windows"
        elif 64 <= ttl < 128:
            os_guess = "Linux/Unix"
        elif ttl < 64:
            os_guess = "Possibly older Unix system or embedded OS"
        else:
            os_guess = "Unknown OS"

        return {
            "status": "success",
            "target": target,
            "ttl": ttl,
            "os_guess": os_guess
        }

    except subprocess.CalledProcessError as e:
        return {
            "status": "error",
            "message": f"Ping failed: {str(e)}"
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"OS detection error: {str(e)}"
        }
