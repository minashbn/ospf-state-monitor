from .docker_utils import *
from flask import  jsonify


def check_system_health() -> dict:
    "Check process stability, log anomalies, and router resource consumption."

    bugs_detected = {
        "process_crash":False
    }
    recent_logs = scan_recent_logs()

    # --- STEP 1: Process and Container Health Validation ---
    container_ok, stdout_run, _ = run_docker_cmd(['inspect', '-f', '{{.State.Running}}', CONTAINER_NAME])
    ospfd_ok, _, _ = run_docker_cmd(['exec', CONTAINER_NAME, 'pgrep', 'ospfd'])
    
    if not container_ok or stdout_run != "true" or not ospfd_ok:
        bugs_detected["process_crash"] = True
        return bugs_detected
    # --- STEP 2: Internal Log Anomaly & Assertion Parsing ---
    log_lower = recent_logs.lower()
    anomaly_patterns = ["assertion failed", "segfault", "malformed packet", "buffer overflow", "out of memory"]
    for pattern in anomaly_patterns:
        if pattern in log_lower:
            bugs_detected["log_anomaly_regression"] = True
            break

    # --- STEP 3: Memory Consumption Resource Tracking ---
    success_mem, stdout_mem, _ = run_docker_cmd(['exec', CONTAINER_NAME, 'ps', '-o', 'vsz,rss', '-C', 'ospfd'])
    if success_mem and "ospfd" in stdout_mem.lower():
        try:
            metrics = stdout_mem.split('\n')[1].split()
            vsz_kb = int(metrics[0])
            if vsz_kb > 256000:
                bugs_detected["memory_leak_warning"] = True
        except Exception:
            pass
    return bugs_detected


