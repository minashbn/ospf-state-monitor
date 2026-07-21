# ospf_handlers/hello.py
from base import OspfPacketHandler, AnalysisContext
from typing import Dict
import ipaddress
from typing import Dict, Any
import re
# {'sent_packet': {'type': 2, 'current_fuzzing_state': 3, 'details': {'router_id': '1.1.1.1', 'seq': 1, 'mtu': 0, 'options': 'E', 'flags': 'MS+M+I', 'init': True, 'more': True, 'master': True, 'lsa_headers': []}}, ''
# 'received_packet': {'type': 2, 'current_fuzzing_state': 3, 'details': {'router_id': '2.2.2.2', 'seq': 891651136, 'mtu': 1500, 'options': 'E', 'flags': 'MS+M+I', 'init': True, 'more': True, 'master': True, 'lsa_headers': []}}}


def clean_state(state_str: str) -> str:
    if not state_str:
        return ""

    # ۱. اگر اسلش دارد، فقط بخش اول (State) را برمی‌داریم
    first_part = state_str.split("/")[0]

    # ۲. حذف تمام کاراکترهای غیر الفبایی (فاصله، خط تیره، انتر، علائم نگارشی و...)
    cleaned = re.sub(r"[^a-zA-Z]", "", first_part)

    # ۳. تبدیل به حروف کوچک
    return cleaned.lower()

class dbd_exstartHandler(OspfPacketHandler):

    def analyze(self, ctx: AnalysisContext) -> Dict[str, bool]:
        # Rule 1: No response received within timeout period
        if ctx.target_packet is None:
            return {"no_response_timeout": True}

        bugs = {}
        target_details = ctx.target_packet.get("details", {})
        pkt_type = ctx.target_packet.get("type")
        

        # --- Context Data Extraction ---
        # Fuzzer (Sender) Parameters
        fuzzer_mtu = ctx.fuzzer_details.get("mtu")
        fuzzer_options = ctx.fuzzer_details.get("options_int", 0)
        fuzzer_init = bool(ctx.fuzzer_details.get("init"))
        fuzzer_more = bool(ctx.fuzzer_details.get("more"))
        fuzzer_master = bool(ctx.fuzzer_details.get("master"))
        fuzzer_seq = ctx.fuzzer_details.get("seq")
        fuzzer_router_id = ctx.fuzzer_details.get("router_id")

        fuzzer_e_bit = bool(fuzzer_options & 0x02)
        fuzzer_n_bit = bool(fuzzer_options & 0x08)

        if pkt_type != 2:
            return {"invalid_packet_type_received": True}

        # Target (Receiver/Local) System State & Expectation

        target_local_mtu = target_details.get("mtu")
        target_options = ctx.global_state.options
        target_e_bit = bool(target_options & 0x02)
        target_n_bit = bool(target_options & 0x08)
        target_seq = target_details.get('seq')

        neighbors=ctx.neighbor_log.get("neighbors", {})
        target_neighbor_state = 'DOWN'
        if fuzzer_router_id in neighbors and len(neighbors[fuzzer_router_id]) > 0:
            neighbor_info = neighbors[fuzzer_router_id][0]
            target_neighbor_state = clean_state(neighbor_info.get("state"))
        print(target_neighbor_state)


        # --- Error Condition Detection ---

        # 1. MTU Mismatch
        mtu_mismatch = fuzzer_mtu > target_local_mtu 

        # 2. Options Mismatch (Area capabilities)
        options_mismatch = (fuzzer_e_bit != target_e_bit) or (fuzzer_n_bit != target_n_bit)

        # 3. Unexpected Control Bits (RFC 2328 Section 10.6)
        # Invalid combinations: Init bit set without Master bit, or Init bit set without More bit
        invalid_control_bits = (fuzzer_init and not fuzzer_master) or (fuzzer_init and not fuzzer_more)

        our_rid = ipaddress.IPv4Address(fuzzer_router_id)
        target_rid = ipaddress.IPv4Address(target_details.get("router_id"))

        if our_rid > target_rid:
            # This should never happen under normal protocol logic.
            is_fuzzer_master = True
        else:
            is_fuzzer_master = False
        seq_valid = ( is_fuzzer_master and target_seq == fuzzer_seq ) or  (not is_fuzzer_master and target_seq != fuzzer_seq)

        malformed_packet=(mtu_mismatch or invalid_control_bits or options_mismatch or not seq_valid)
        
        # --- RFC Conformance Validation ---

        # Case A: Malformed packet sent -> Target must NOT transition to Exchange state
        if malformed_packet:
            if target_neighbor_state.lower()=="exchange" :
                
                if mtu_mismatch:
                    bugs["rfc_mtu_mismatch_accepted"] = True
                if options_mismatch:
                    bugs["rfc_options_mismatch_accepted"] = True
                if invalid_control_bits:
                    bugs["rfc_invalid_control_bits_accepted"] = True
                if not seq_valid:
                    bugs["invalid_seq_selected"]=True


        # Case B: Valid ExStart negotiation -> Target should progress or respond
        else:
            # If valid packet sent but target unexpectedly drops adjacency or resets to Down/Init
            if target_neighbor_state.lower() in ["down", "init"] :
                bugs["rfc_valid_exstart_rejected"] = True
            

        return bugs

