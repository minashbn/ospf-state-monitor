from typing import Dict, Any , Optional
from base import OspfPacketHandler
from ospf_handlers.hello_2way import *

_REGISTRY: Dict[int, OspfPacketHandler] = {
    2: hello_2wayHandler()  
    # 4: OspfLsuHandler(),    # نوع ۴ مربوط به بسته‌های LSU
}

def get_handler(packet_type: int) -> Optional[OspfPacketHandler]:
    """Retrieve the handler for the packet type using a direct lookup."""
    return _REGISTRY.get(packet_type)
