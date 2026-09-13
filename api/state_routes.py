from flask import Blueprint, request, jsonify
from core.ospf_state import global_ospf_state 

state_blueprint = Blueprint('state_routes', __name__)

@state_blueprint.route("/valid_2way", methods=["POST"])
def valid_2way():
    payload = request.get_json()
    if not payload:
        return jsonify({"error": "Invalid request payload"}), 400

    try:
        global_ospf_state.update_from_json(payload)
    except Exception as e:
        return jsonify({"error": f"Failed to store state: {str(e)}"}), 500

    return jsonify({
        "status": "success", 
        "message": "Payload registered into global state successfully."
    }), 200