from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any




@dataclass
class OspfValidationState:
    options: Optional[str] = None
    netmask: Optional[str] = None
    hello_interval: Optional[int] = None
    dead_interval: Optional[int] = None
    mtu: Optional[int] =None
    

    def update_from_json(self, data: Dict[str, Any]):
        self.options = data.get("options", self.options)
        self.netmask = data.get("netmask", self.netmask)
        self.hello_interval = data.get("hello_interval", self.hello_interval)
        self.dead_interval = data.get("dead_interval", self.dead_interval)
        self.mtu = data.get("mtu",self.mtu)

global_ospf_state = OspfValidationState()
