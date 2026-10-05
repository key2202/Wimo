"""Scanner jaringan - auto ping sweep + ip neigh. Tidak butuh pancing manual."""
import socket
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from .vendor import VendorDetector


class NetworkScanner:
    def __init__(self, interface):
        self.iface = interface
        self.detector = VendorDetector()
        self.hosts = []

    def _get_cidr(self):
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show", self.iface],
                text=True, timeout=2)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1]
        except Exception:
            pass
        return "192.168.1.0/24"

    def _ping_one(self, ip):
        """Ping satu IP, timeout cepat."""
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2)
        except Exception:
            pass

    def _ping_sweep(self, cidr):
        """Ping semua IP di subnet secara paralel."""
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            targets = [str(ip) for ip in net.hosts()]
        except Exception:
            return 0

        # Batasi maksimum 1024 IP (untuk /22 atau lebih kecil)
        if len(targets) > 1024:
            targets = targets[:1024]

        total = len(targets)
        done = 0

        # 128 worker paralel = cepat
        with ThreadPoolExecutor(max_workers=128) as ex:
            futs = [ex.submit(self._ping_one, ip) for ip in targets]
            for _ in as_completed(futs):
                done += 1

        return total

    def _resolve_hostname(self, ip):
        try:
            socket.setdefaulttimeout(0.4)
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def scan(self):
        cidr = self._get_cidr()
        print(f"   [i] Interface : {self.iface}", flush=True)
        print(f"   [i] CIDR      : {cidr}", flush=True)

        # === LANGKAH 1: Ping sweep semua IP di subnet ===
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            total_ips = len(list(net.hosts()))
            if total_ips > 1024:
                total_ips = 1024
        except Exception:
            total_ips = 254

        print(f"   [i] Ping sweep {total_ips} IP (paralel, tunggu...)",
              flush=True)
        self._ping_sweep(cidr)
        print(f"   [i] Ping sweep selesai. Baca ARP table...", flush=True)

        # === LANGKAH 2: Baca ARP table ===
        hosts_raw = []
        try:
            out = subprocess.check_output(
                ["ip", "neigh", "show", "dev", self.iface],
                text=True, timeout=3)
            for line in out.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                ip = parts[0]
                if ":" in ip:
                    continue
                if "lladdr" not in parts:
                    continue
                mac = parts[parts.index("lladdr") + 1]
                if "FAILED" in parts or "INCOMPLETE" in parts:
                    continue
                hosts_raw.append((ip, mac))
        except Exception as e:
            print(f"   [!] Error baca ARP: {e}", flush=True)

        print(f"   [i] ARP table berisi {len(hosts_raw)} device.", flush=True)
        print(f"   [i] Resolve hostname...", flush=True)

        # === LANGKAH 3: Resolve hostname + detect vendor ===
        self.hosts = []
        with ThreadPoolExecutor(max_workers=16) as ex:
            futs = {ex.submit(self._resolve_hostname, ip): (ip, mac)
                    for ip, mac in hosts_raw}
            for fut in futs:
                ip, mac = futs[fut]
                try:
                    hostname = fut.result(timeout=2)
                except Exception:
                    hostname = ""
                info = self.detector.detect(mac, hostname)
                self.hosts.append({
                    "id": len(self.hosts) + 1,
                    "ip": ip, "mac": mac,
                    "hostname": hostname or "-",
                    "vendor": info["vendor"],
                    "type": info["type"],
                    "status": "free",
                    "rate": "-",
                })

        self.hosts.sort(key=lambda h: tuple(map(int, h["ip"].split("."))))
        for i, h in enumerate(self.hosts, 1):
            h["id"] = i
        return self.hosts
