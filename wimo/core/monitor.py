"""Monitoring bandwidth per-host secara live."""
import time
from scapy.all import AsyncSniffer, IP
from collections import defaultdict

class BandwidthMonitor:
    def __init__(self, interface: str):
        self.iface = interface
        self.counters = defaultdict(lambda: {"rx": 0, "tx": 0, "last": time.time()})
        self._sniffer = None

    def _handle(self, pkt):
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            size = len(pkt)
            self.counters[src]["tx"] += size
            self.counters[dst]["rx"] += size

    def start(self):
        self._sniffer = AsyncSniffer(iface=self.iface, prn=self._handle, store=False)
        self._sniffer.start()

    def snapshot(self) -> dict:
        now = time.time()
        out = {}
        for ip, c in self.counters.items():
            dt = max(now - c["last"], 1e-6)
            out[ip] = {
                "rx_kbps": (c["rx"] * 8) / dt / 1000,
                "tx_kbps": (c["tx"] * 8) / dt / 1000,
            }
            c["rx"] = c["tx"] = 0
            c["last"] = now
        return out

    def stop(self):
        if self._sniffer:
            self._sniffer.stop()
