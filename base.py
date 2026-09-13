# ospf_handlers/base.py
from abc import ABC, abstractmethod
from typing import Dict, Any , Optional

class AnalysisContext:
    """Wrap input data to avoid changing method signatures in the future."""

    def __init__(
        self,
        fuzzer_details: Dict[str, Any],
        target_packet: Dict[str, Any],
        global_state: Any,
        neighbor_log:Any
    ):
        self.fuzzer_details = fuzzer_details
        self.target_packet = target_packet
        self.global_state = global_state
        self.neighbor_log = neighbor_log


class OspfPacketHandler(ABC):


    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> Dict[str, bool]:
        """Execute the validation logic and return the detected bugs."""
        pass




