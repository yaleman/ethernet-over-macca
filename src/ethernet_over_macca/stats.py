from dataclasses import dataclass


@dataclass
class PayloadStats:
    payload_size: int
    total_size: int
    header_size: int
    overhead_ratio: float
    efficiency_percent: float
