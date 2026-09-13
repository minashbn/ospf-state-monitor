from typing import Dict, Any , Optional
from base import OspfPacketHandler
from ospf_handlers.hello_2way import *
from ospf_handlers.exstart import *
from ospf_handlers.exchange import *

_REGISTRY: Dict[int, OspfPacketHandler] = {
    2: hello_2wayHandler() , 
    3: dbd_exstartHandler(),
    4: dbd_exchangeHandler(),
}

def get_handler(packet_type: int) -> Optional[OspfPacketHandler]:
    """Retrieve the handler for the packet type using a direct lookup."""
    return _REGISTRY.get(packet_type)
