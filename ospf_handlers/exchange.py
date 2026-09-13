# ospf_handlers/hello.py
from base import OspfPacketHandler, AnalysisContext
from typing import Dict
import ipaddress
from typing import Dict, Any
from .utils import *
# {'sent_packet': {'type': 2, 'current_fuzzing_state': 4, 'details': {'router_id': '1.1.1.1', 'seq': 1037335533, 'mtu': 0, 'options': 'E', 'options_int': 2, 'flags': '', 'init': False, 'more': False, 'master': False
# , 'lsa_headers': [{'type': 7, 'id': '10.0.0.1', 'adv_router': '10.0.0.1', 'seq': 2147483649, 'age': 1, 'chksum': 34236}]}}, 
#  'received_packet': {'type': 2, 'current_fuzzing_state': 4, 'details': {'router_id': '2.2.2.2', 'seq': 1037335533, 'mtu': 1500, 'options': 'E', 'options_int': 2, 'flags': 'MS+M+I', 'init': True, 'more': True, 'master': True, 'lsa_headers': []}}}




class dbd_exchangeHandler(OspfPacketHandler):

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
        target_init = bool(target_details.get("init"))
        target_more = bool(target_details.get("more"))
        target_master = bool(target_details.get("master"))
        

        neighbors=ctx.neighbor_log.get("neighbors", {})
        target_neighbor_state = 'DOWN'
        if fuzzer_router_id in neighbors and len(neighbors[fuzzer_router_id]) > 0:
            neighbor_info = neighbors[fuzzer_router_id][0]
            target_neighbor_state = clean_state(neighbor_info.get("state"))
        print(target_neighbor_state)


        # --- Error Condition Detection ---

        # 1. MTU Mismatch
        mtu_mismatch =(fuzzer_mtu != 0) and fuzzer_mtu > target_local_mtu 

        # 2. Options Mismatch (Area capabilities)
        options_mismatch = (fuzzer_e_bit != target_e_bit) or (fuzzer_n_bit != target_n_bit)


        our_rid = ipaddress.IPv4Address(fuzzer_router_id)
        target_rid = ipaddress.IPv4Address(target_details.get("router_id"))


        malformed_packet=(mtu_mismatch or options_mismatch)
        
        # --- RFC Conformance Validation ---

        # Case A: Malformed packet sent -> Target must NOT transition to Exchange state
        if malformed_packet:
            if target_neighbor_state.lower()=="exchange" :
                if mtu_mismatch:
                    bugs["rfc_mtu_mismatch_accepted"] = True
                if options_mismatch:
                    bugs["rfc_options_mismatch_accepted"] = True
                
                invalid_control_seq = (fuzzer_init == 1) or (target_init == 1)

                if our_rid > target_rid:
                    invalid_control_seq = fuzzer_master != 1 or fuzzer_seq != target_seq
                else:
                    invalid_control_seq = target_master != 1 or target_seq-fuzzer_seq != 1

                
              
                if invalid_control_seq:
                    bugs["rfc_invalid_control_bits_or_sequence_number_accepted"] = True

            elif target_neighbor_state.lower()=="exstart":
                invalid_control_bits = (fuzzer_init and not fuzzer_master) or (fuzzer_init and not fuzzer_more)

                if invalid_control_bits:
                    bugs["rfc_invalid_control_bits_accepted"] = True

        # Case B: Valid ExStart negotiation -> Target should progress or respond
        else:
            # If valid packet sent but target unexpectedly drops adjacency or resets to Down/Init
            if target_neighbor_state.lower() in ["down", "init","exstart"] :
                bugs["rfc_valid_exstart_rejected"] = True
            

        return bugs

