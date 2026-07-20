from flask import Flask, request, jsonify
from base import *
from registry import *
from core.ospf_state import global_ospf_state 
from core.runtime_check import *
from config import *
from api.state_routes import state_blueprint 


app = Flask(__name__)

app.register_blueprint(state_blueprint)



@app.route('/analyze_step', methods=['POST'])
def analyze_step():
    """
    Main endpoint for receiving data from the fuzzer and analyzing the OSPF state.
    """
    payload = request.json
    if not payload:
        return jsonify({"error": "Invalid request payload"}), 400

    fuzzer_packet = payload.get("sent_packet", {})
    target_packet = payload.get("received_packet", {})

    fuzzer_state = fuzzer_packet.get("current_fuzzing_state")
    fuzzer_details = fuzzer_packet.get("details", {})


    if not fuzzer_details or not target_packet:
        return jsonify({"error": "Missing data"}), 400

    # 2. Create the analysis context for the packet handlers
    ctx = AnalysisContext(
        fuzzer_details=fuzzer_details,
        target_packet=target_packet,
        global_state=global_ospf_state
    )

    # 3. Select the appropriate handler based on the fuzzing type
    handler = get_handler(fuzzer_state)

    bugs_detected = check_system_health()
    if handler:
        # Execute the packet-specific analysis logic (e.g., HelloHandler or DBDescHandler)
        logical_bugs = handler.analyze(ctx)
        bugs_detected.update(logical_bugs)
    else:
        # No handler is implemented for this packet type
        bugs_detected["unknown_packet_type_bypass"] = True

    # 4. Return the analysis results to the fuzzer or monitoring system
    return jsonify({
        "status": "success",
        "bugs_detected": bugs_detected
    })


@app.route("/reset_ospf")
def reset_ospf():
    success = False
    try:
        # Use 'docker' and 'compose' as separate arguments.
        # This is the standard approach on modern Linux distributions.

        # Step 1: Stop and remove the containers.
        subprocess.run(
            ['docker', 'compose', 'down'],
            cwd=COMPOSE_FILE_PATH,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30
        )

        # Step 2: Recreate and start the containers.
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

    # Always return a response outside the try/except block,
    # regardless of whether the reset succeeds or fails.
    return jsonify({"reset": "ok" if success else "failed"})


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



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
