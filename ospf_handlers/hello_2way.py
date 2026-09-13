# ospf_handlers/hello.py
from base import OspfPacketHandler, AnalysisContext
from typing import Dict
from .utils import *


class hello_2wayHandler(OspfPacketHandler):

    def analyze(self, ctx: AnalysisContext) -> Dict[str, bool]:
        
        if ctx.target_packet is None:
            return {"no_response_timeout":True}
        
        bugs = {}
        target_details = ctx.target_packet.get("details", {})
        fuzzer_router_id = ctx.fuzzer_details.get("router_id")
        fuzzer_options = ctx.fuzzer_details.get("options_int", 0)

        # Extract local target profile directly from the wire packet
        fuzzer_e_bit = bool(fuzzer_options & 0x02)
        fuzzer_n_bit = bool(fuzzer_options & 0x08)

        pkt_type = ctx.target_packet.get("type")
        
        if pkt_type == 1:
            recv_options = target_details.get("options_int", 0)
            target_e_bit = bool(recv_options & 0x02)
            target_n_bit = bool(recv_options & 0x08)
        elif pkt_type == 2:
            target_e_bit = bool(ctx.global_state.options & 0x02) if ctx.global_state.options else False
            target_n_bit = bool(ctx.global_state.options & 0x08) if ctx.global_state.options else False
        else:
            return {"state_bypass": True}

        #  Verify if a mismatch actually fooled the target
        has_mismatch = (
            fuzzer_e_bit != target_e_bit or
            fuzzer_n_bit != target_n_bit or
            ctx.fuzzer_details.get("hello_interval") != ctx.global_state.hello_interval or
            ctx.fuzzer_details.get("dead_interval") != ctx.global_state.dead_interval
        )

        target_neighbors = target_details.get("neighbors", [])
        neighbors=ctx.neighbor_log.get("neighbors", {})
        state = 'DOWN'
        if fuzzer_router_id in neighbors and len(neighbors[fuzzer_router_id]) > 0:
            neighbor_info = neighbors[fuzzer_router_id][0]
            state = neighbor_info.get("state")
            state=clean_state(state)

        is_accepted = state.lower()=="init" or pkt_type == 2 
        

        if has_mismatch and is_accepted:
            bugs["rfc_invalid_state_acceptance" if pkt_type == 1 else "state_bypass"] = True
        if not has_mismatch and not is_accepted:
            bugs["rfc_valid_state_rejection"] = True

        return bugs


