import json

class Rule:
    def __init__(self,
                 name,
                 src_addr,
                 src_mask,
                 src_port_min,
                 src_port_max,
                 dst_addr,
                 dst_mask,
                 dst_port_min,
                 dst_port_max,
                 action,
                 protocol
                 ) -> None:
        self.name = name
        self.src_addr = src_addr
        self.src_mask = src_mask
        self.src_port_min = src_port_min
        self.src_port_max = src_port_max
        self.dst_addr = dst_addr
        self.dst_mask = dst_mask
        self.dst_port_min = dst_port_min
        self.dst_port_max = dst_port_max
        self.action = action
        self.protocol = protocol

    def dump(self) -> str:
        return json.dumps({
            "name": self.name,
            "src": {
                "addr": self.src_addr,
                "mask": self.src_mask,
                "port_mix": self.src_port_min,
                "port_max": self.src_port_max,
            },
            "dst": {
                "addr": self.dst_addr,
                "mask": self.dst_mask,
                "port_mix": self.dst_port_min,
                "port_max": self.dst_port_max,
            },
            "action": self.action,
            "protocol": self.protocol
        }, indent=4)