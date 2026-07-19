import subprocess
from flask import Flask, jsonify, request
import os
import sys
import re
import json
from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any

COMPOSE_FILE_PATH = "/home/mina/Desktop/boofuzz/boofuzz/" 

app = Flask(__name__)

CONTAINER_NAME = "r1"
INTERFACE_NAME = "eth0"  # Target interface name inside the container
LOG_FILE_PATH = "/var/log/frr/frr.log"  # Adjust if your container logs OSPF elsewhere

@dataclass
class OspfValidationState:
    options: Optional[str] = None
    netmask: Optional[str] = None
    hello_interval: Optional[int] = None
    dead_interval: Optional[int] = None

    def update_from_json(self, data: Dict[str, Any]):
        """متدی برای آپدیت آسان مقادیر کلاس"""
        self.options = data.get("options", self.options)
        self.netmask = data.get("netmask", self.netmask)
        self.hello_interval = data.get("hello_interval", self.hello_interval)
        self.dead_interval = data.get("dead_interval", self.dead_interval)

global_ospf_state = OspfValidationState()

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


@app.route("/analyze_step", methods=["POST"])
def analyze_step():
    """
    Executes the 6-Step Validation Pipeline by cross-referencing I/O payloads
    with the FRR daemon's internal state machine, active logs, and structural requirements.
    """
    payload = request.get_json()
    if not payload:
        return jsonify({"error": "Invalid request payload"}), 400

    fuzzer_packet = payload.get("sent_packet", {})
    target_packet = payload.get("received_packet", {})
    
    fuzzer_state = fuzzer_packet.get("current_fuzzing_state")
    fuzzer_details = fuzzer_packet.get("details", {})
    target_details = target_packet.get("details", {})
    
    fuzzer_router_id = fuzzer_details.get("router_id")
    
    # Fetch FRR memory structures and logs
    frr_neighbors = get_frr_internal_neighbors_json()
    recent_logs = scan_recent_logs()

    # 6-Step Failure & Bug Detection Suite
    bugs_detected = {
        "process_crash": False,
        "rfc_compliance_violation": False,
        "state_bypass": False,
        "log_anomaly_regression": False,
        "memory_leak_warning": False
    }

    # --- STEP 1: Process and Container Health Validation ---
    container_ok, stdout_run, _ = run_docker_cmd(['inspect', '-f', '{{.State.Running}}', CONTAINER_NAME])
    ospfd_ok, _, _ = run_docker_cmd(['exec', CONTAINER_NAME, 'pgrep', 'ospfd'])
    
    if not container_ok or stdout_run != "true" or not ospfd_ok:
        bugs_detected["process_crash"] = True
        return jsonify({"status": "unhealthy", "bugs": bugs_detected, "reason": "OSPFD daemon crashed or container halted"}), 503

    # --- STEP 2: RFC Compliance & Parametric Validation ---
    # Compare fuzzer's options bitmask against the target's baseline parsed above
    fuzzer_options= fuzzer_details.get("options_int")


    fuzzer_e_bit = bool(fuzzer_options & 0x02)
    fuzzer_n_bit = bool(fuzzer_options & 0x08)

    if target_packet.get("type")==1:
        # --- DYNAMIC OPTIMIZATION: Extract local target profile directly from the wire packet ---
        recv_options=target_details.get("options_int")
    

        # Extract dynamic E and N bits directly from what the target actually sent
        target_local_e_bit = bool(recv_options & 0x02)
        target_local_n_bit = bool(recv_options & 0x08)
    else:
        if target_packet.get("type")==2:
            target_local_e_bit = bool(global_ospf_state.options & 0x02)
            target_local_n_bit = bool(global_ospf_state.options & 0x08)
        else:
            bugs_detected["state_bypass"] = True
        
    # 2. Verify if a mismatch actually fooled the target
    if target_packet:
        target_announced_neighbors = target_details.get("neighbors", []) 
        
        has_mismatch = (fuzzer_e_bit != target_local_e_bit) or \
                                (fuzzer_n_bit != target_local_n_bit) or \
                                (fuzzer_details.get("hello_interval") != global_ospf_state.hello_interval) or \
                                (fuzzer_details.get("dead_interval") != global_ospf_state.dead_interval)
                
        is_fuzzer_accepted = fuzzer_router_id in target_announced_neighbors or target_packet.get("type")==2

        if has_mismatch and is_fuzzer_accepted:
            if target_packet.get("type")==1:
                bugs_detected["rfc_invalid_state_acceptance"] = True
            else:
                bugs_detected["state_bypass"] = True
        if not has_mismatch and not is_fuzzer_accepted:
            bugs_detected["rfc_valid_state_rejection"] = True


       
        
    # --- STEP 4: Internal Log Anomaly & Assertion Parsing ---
    log_lower = recent_logs.lower()
    anomaly_patterns = ["assertion failed", "segfault", "malformed packet", "buffer overflow", "out of memory"]
    for pattern in anomaly_patterns:
        if pattern in log_lower:
            bugs_detected["log_anomaly_regression"] = True
            break

    # --- STEP 5: Memory Consumption Resource Tracking ---
    success_mem, stdout_mem, _ = run_docker_cmd(['exec', CONTAINER_NAME, 'ps', '-o', 'vsz,rss', '-C', 'ospfd'])
    if success_mem and "ospfd" in stdout_mem.lower():
        try:
            metrics = stdout_mem.split('\n')[1].split()
            vsz_kb = int(metrics[0])
            if vsz_kb > 256000:
                bugs_detected["memory_leak_warning"] = True
        except Exception:
            pass

    has_vulnerabilities = any(bugs_detected.values())
    status_code = 503 if has_vulnerabilities else 200

    return jsonify({
        "status": "vulnerable" if has_vulnerabilities else "stable",
        "bugs_detected": bugs_detected,
    }), status_code



@app.route("/valid_2way", methods=["POST"])
def valid_2way():
    payload = request.get_json()
    if not payload:
        return jsonify({"error": "Invalid request payload"}), 400

    # ۳. ذخیره‌سازی داده‌ها در آبجکت گلوبal
    try:
        global_ospf_state.update_from_json(payload)
    except Exception as e:
        return jsonify({"error": f"Failed to store state: {str(e)}"}), 500

    # در اینجا می‌توانید مراحل پایپ‌لاین اعتبارسنجی را ادامه دهید
    # و به داده‌های ذخیره شده دسترسی داشته باشید: global_ospf_state.hello_interval
    print(global_ospf_state)

    return jsonify({
        "status": "success", 
        "message": "Payload registered into global state successfully."
    }), 200



@app.route("/health")
def health():
    try:
        success, stdout, _ = run_docker_cmd(['inspect', '-f', '{{.State.Running}}', CONTAINER_NAME])
        if not success or stdout != "true":
            return jsonify({"status": "unhealthy", "reason": "container_not_running"}), 503
        
        ospfd_ok, _, _ = run_docker_cmd(['exec', CONTAINER_NAME, 'pgrep', 'ospfd'])
        if not ospfd_ok:
            return jsonify({"status": "unhealthy", "reason": "ospfd_not_running"}), 503
        
        return jsonify({"status": "healthy"}), 200
    except Exception as e:
        return jsonify({"status": "unhealthy", "reason": "check_failed", "error": str(e)}), 503

@app.route("/status")
def status():
    success, stdout, _ = run_docker_cmd(['inspect', '-f', '{{.State.Running}}', CONTAINER_NAME])
    is_running = stdout == "true"
    ospfd_ok, _, _ = run_docker_cmd(['exec', CONTAINER_NAME, 'pgrep', 'ospfd'])
    
    return jsonify({
        "container_running": is_running,
        "ospfd_running": bool(ospfd_ok),
        "crashed": not (is_running and ospfd_ok)
    })

@app.route("/reset_ospf")
def reset_ospf():
    success = False
    try:
        # استفاده از 'docker' و 'compose' به عنوان آرگومان‌های جداگانه
        # این روش در لینوکس‌های جدید استاندارد است
        
        # گام اول: پایین آوردن کانتینر
        subprocess.run(
            ['docker', 'compose', 'down'],
            cwd=COMPOSE_FILE_PATH,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30
        )

        # گام دوم: بالا آوردن مجدد
        result = subprocess.run(
            ['docker', 'compose', 'up', '-d', '--force-recreate'],
            cwd=COMPOSE_FILE_PATH,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30
        )

        if result.returncode == 0:
            success = True
        else:
            print(f"Docker compose up failed with error: {result.stderr}")

    except Exception as e:
        print(f"Exception during reset: {str(e)}")
        success = False

    # حتماً return باید خارج از بلوک try/except باشد تا در هر شرایطی پاسخ برگردد
    return jsonify({"reset": "ok" if success else "failed"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)