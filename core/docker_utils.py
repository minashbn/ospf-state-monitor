import subprocess
from config import *
import json


def run_docker_cmd(cmd_list):
    """Executes a command against the target docker container securely."""
    try:
        result = subprocess.run(
            ['docker'] + cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            text=True
        )
        return result.returncode == 0, result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return False, "", str(e)

def get_frr_internal_neighbors_json():
    """ Fetches live OSPF neighbor memory mapping using JSON formatting directly from vtysh. """
    success, output, _ = run_docker_cmd(['exec', CONTAINER_NAME, 'vtysh', '-c', 'show ip ospf neighbor json'])
    if success and output:
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            pass
    return {}

def scan_recent_logs():
    """ Scans the tail end of the routing log inside the container for anomaly signatures. """
    success, output, _ = run_docker_cmd(['exec', CONTAINER_NAME, 'tail', '-n', '50', LOG_FILE_PATH])
    if not success:
        return ""
    return output
