"""WiMO CLI - prompt interaktif pink (versi anti-hang)."""
import subprocess
import time
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel
from rich.live import Live
from rich.table import Table

from .ui.theme import Pink
from .ui.banner import show_banner
from .ui.tables import hosts_table

console = Console()


def detect_iface():
    try:
        out = subprocess.check_output(
            ["ip", "route", "get", "1.1.1.1"],
            text=True, timeout=3, stderr=subprocess.DEVNULL)
        toks = out.split()
        if "dev" in toks:
            return toks[toks.index("dev") + 1]
    except Exception:
        pass
    return None


def detect_gateway():
    try:
        out = subprocess.check_output(
            ["ip", "route"], text=True, timeout=3,
            stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            if line.startswith("default"):
                return line.split()[2]
    except Exception:
        pass
    return None


HELP_TEXT = """
[bold #FF1493]Perintah WiMO:[/]
  [bold #FF69B4]scan[/]                 Pindai jaringan
  [bold #FF69B4]hosts[/]                Tampilkan daftar device
  [bold #FF69B4]limit <id> <rate>[/]    Batasi bandwidth (cth: limit 3 500kbit)
  [bold #FF69B4]block <id>[/]           Blokir akses internet (satu device)
  [bold #FF69B4]blockall[/]             Blokir SEMUA device sekaligus
  [bold #FF69B4]free <id>[/]            Hapus pembatasan satu device
  [bold #FF69B4]freeall[/]              Bebaskan SEMUA device sekaligus
  [bold #FF69B4]monitor[/]              Mode monitoring live (Ctrl+C keluar)
  [bold #FF69B4]info <id>[/]            Detail device
  [bold #FF69B4]alias <id> <nama>[/]    Beri nama custom ke device
  [bold #FF69B4]ping <id>[/]            Ping device
  [bold #FF69B4]stats[/]                Statistik jaringan
  [bold #FF69B4]audit[/]                Audit keamanan jaringan
  [bold #FF69B4]watchdog[/]             Auto-scan tiap 60 detik
  [bold #FF69B4]report[/]               Laporan Markdown + HTML
  [bold #FF69B4]export[/]               Export device ke CSV
  [bold #FF69B4]help[/]                 Tampilkan bantuan
  [bold #FF69B4]quit[/] / [bold #FF69B4]exit[/]         Keluar
"""


class WiMO:
    def __init__(self):
        self.iface = detect_iface()
        self.gateway = detect_gateway()
        self.scanner = None
        self.arp = None
        self.traffic = None
        self.monitor = None
        self.hosts = []

    def _init_scanner(self):
        if self.scanner is None:
            from .core.scanner import NetworkScanner
            self.scanner = NetworkScanner(self.iface)
        return self.scanner

    def _init_arp(self):
        if self.arp is None:
            from .core.arp_engine import ARPEngine
            self.arp = ARPEngine(self.iface)
        return self.arp

    def _init_traffic(self):
        if self.traffic is None:
            from .core.traffic import TrafficController
            self.traffic = TrafficController(self.iface)
        return self.traffic

    def _init_monitor(self):
        if self.monitor is None:
            from .core.monitor import BandwidthMonitor
            self.monitor = BandwidthMonitor(self.iface)
        return self.monitor

    def _get_host(self, hid):
        for h in self.hosts:
            if h["id"] == hid:
                return h
        return None

    def cmd_scan(self):
        scanner = self._init_scanner()
        console.print(f"[{Pink.HOT}]Memindai {self.iface}...[/]")
        self.hosts = scanner.scan()
        console.print(hosts_table(self.hosts))

    def cmd_hosts(self):
        if not self.hosts:
            console.print(f"[{Pink.WARN}]Belum ada data. Jalankan 'scan' dulu.[/]")
            return
        console.print(hosts_table(self.hosts))

    def cmd_limit(self, hid, rate):
        h = self._get_host(hid)
        if not h:
            console.print(f"[{Pink.ERROR}]ID {hid} tidak ditemukan.[/]")
            return
        arp = self._init_arp()
        traffic = self._init_traffic()
        if not arp.start(h["ip"], self.gateway):
            console.print(f"[{Pink.ERROR}]Gagal ARP spoof ke {h['ip']}.[/]")
            return
        kbit = self._parse_rate(rate)
        traffic.limit(h["ip"], kbit)
        h["status"] = "limited"
        h["rate"] = f"{kbit} kbit"
        console.print(f"[{Pink.OK}]Limit {h['ip']} -> {kbit} kbit/s[/]")

    def cmd_block(self, hid):
        h = self._get_host(hid)
        if not h:
            console.print(f"[{Pink.ERROR}]ID {hid} tidak ditemukan.[/]")
            return
        arp = self._init_arp()
        traffic = self._init_traffic()
        if not arp.start(h["ip"], self.gateway):
            console.print(f"[{Pink.ERROR}]Gagal ARP spoof.[/]")
            return
        traffic.block(h["ip"])
        h["status"] = "blocked"
        h["rate"] = "0 kbit"
        console.print(f"[{Pink.OK}]Blokir {h['ip']}[/]")

    def cmd_blockall(self):
        if not self.hosts:
            console.print(f"[{Pink.WARN}]Belum ada data. Jalankan 'scan' dulu.[/]")
            return
        console.print(f"[{Pink.WARN}]Memblokir {len(self.hosts)} device...[/]")
        arp = self._init_arp()
        traffic = self._init_traffic()
        ok = 0
        fail = 0
        for h in self.hosts:
            try:
                if not arp.start(h["ip"], self.gateway):
                    console.print(f"  [{Pink.ERROR}]x[/] {h['ip']} - gagal ARP spoof")
                    fail += 1
                    continue
                traffic.block(h["ip"])
                h["status"] = "blocked"
                h["rate"] = "0 kbit"
                console.print(f"  [{Pink.OK}]v[/] {h['ip']} diblokir")
                ok += 1
            except Exception as e:
                console.print(f"  [{Pink.ERROR}]x[/] {h['ip']} - {e}")
                fail += 1
        console.print(f"[{Pink.OK}]Selesai. {ok} diblokir, {fail} gagal.[/]")

    def cmd_freeall(self):
        if not self.hosts:
            console.print(f"[{Pink.WARN}]Belum ada data. Jalankan 'scan' dulu.[/]")
            return
        console.print(f"[{Pink.WARN}]Membebaskan {len(self.hosts)} device...[/]")
        ok = 0
        for h in self.hosts:
            try:
                if self.traffic:
                    self.traffic.free(h["ip"])
                if self.arp:
                    self.arp.restore(h["ip"], self.gateway)
                h["status"] = "free"
                h["rate"] = "-"
                console.print(f"  [{Pink.OK}]v[/] {h['ip']} dibebaskan")
                ok += 1
            except Exception as e:
                console.print(f"  [{Pink.ERROR}]x[/] {h['ip']} - {e}")
        console.print(f"[{Pink.OK}]Selesai. {ok} device dibebaskan.[/]")

    def cmd_alias(self, hid, name):
        """Beri nama custom ke device."""
        h = self._get_host(hid)
        if not h:
            console.print(f"[{Pink.ERROR}]ID {hid} tidak ditemukan.[/]")
            return
        old_name = h.get("alias", h.get("hostname", "-"))
        h["alias"] = name
        console.print(f"[{Pink.OK}]v Device {hid}: '{old_name}' -> '{name}'[/]")

    def cmd_ping(self, hid):
        """Ping device untuk cek online."""
        h = self._get_host(hid)
        if not h:
            console.print(f"[{Pink.ERROR}]ID {hid} tidak ditemukan.[/]")
            return
        import subprocess
        console.print(f"[{Pink.HOT}]Ping {h['ip']}...[/]")
        try:
            result = subprocess.run(
                ["ping", "-c", "3", "-W", "2", h["ip"]],
                capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                # Parse RTT
                for line in result.stdout.splitlines():
                    if "rtt" in line or "round-trip" in line:
                        console.print(f"[{Pink.OK}]v {h['ip']} ONLINE[/]")
                        console.print(f"   [{Pink.INFO}]{line.strip()}[/]")
                        return
                console.print(f"[{Pink.OK}]v {h['ip']} ONLINE[/]")
            else:
                console.print(f"[{Pink.ERROR}]x {h['ip']} TIDAK MERESPON[/]")
        except subprocess.TimeoutExpired:
            console.print(f"[{Pink.ERROR}]x {h['ip']} timeout[/]")
        except Exception as e:
            console.print(f"[{Pink.ERROR}]Error: {e}[/]")

    def cmd_watchdog(self, interval=60):
        """Auto-scan tiap N detik, deteksi device baru."""
        console.print(f"[{Pink.OK}]Watchdog aktif. Interval: {interval}s[/]")
        console.print(f"[{Pink.DIM}]Tekan Ctrl+C untuk stop.[/]\n")
        prev_ips = set(h["ip"] for h in self.hosts) if self.hosts else set()
        scan_count = 0
        try:
            while True:
                time.sleep(interval)
                scan_count += 1
                scanner = self._init_scanner()
                new_hosts = scanner.scan()
                curr_ips = set(h["ip"] for h in new_hosts)
                added = curr_ips - prev_ips
                removed = prev_ips - curr_ips
                self.hosts = new_hosts
                console.print(f"[{Pink.INFO}][Scan #{scan_count}] "
                              f"{len(self.hosts)} device[/]")
                if added:
                    console.print(f"[{Pink.HOT}][!] Device BARU:[/]")
                    for ip in added:
                        for h in self.hosts:
                            if h["ip"] == ip:
                                console.print(f"   [{Pink.OK}]+ {ip} "
                                              f"({h['vendor']}) - {h['type']}[/]")
                if removed:
                    console.print(f"[{Pink.WARN}][-] Hilang: {', '.join(removed)}[/]")
                prev_ips = curr_ips
        except KeyboardInterrupt:
            console.print(f"\n[{Pink.WARN}]Watchdog dihentikan.[/]")

    def cmd_stats(self):
        """Statistik jaringan."""
        if not self.hosts:
            console.print(f"[{Pink.WARN}]Belum ada data. Jalankan 'scan' dulu.[/]")
            return
        from collections import Counter
        vendors = Counter(h.get("vendor", "Unknown") for h in self.hosts)
        types = Counter(h.get("type", "Unknown") for h in self.hosts)
        total = len(self.hosts)
        routers = sum(1 for h in self.hosts
                      if "Router" in h.get("type", "") or "Router" in h.get("vendor", ""))
        clients = total - routers

        lines = []
        lines.append(f"[{Pink.HOT}]Total device   :[/] {total}")
        lines.append(f"[{Pink.HOT}]Router/AP      :[/] {routers}")
        lines.append(f"[{Pink.HOT}]Client         :[/] {clients}")
        lines.append("")
        lines.append(f"[bold {Pink.ROSE}]Vendor breakdown:[/]")
        for v, c in vendors.most_common(8):
            lines.append(f"   {v:<22} : {c}")
        lines.append("")
        lines.append(f"[bold {Pink.ROSE}]Type breakdown:[/]")
        for t, c in types.most_common(8):
            lines.append(f"   {t:<22} : {c}")

        console.print(Panel("\n".join(lines),
                            title=f"[bold {Pink.MAGENTA}]Network Stats[/]",
                            border_style=Pink.ROSE))

    def cmd_audit(self):
        """Audit keamanan jaringan - cek kerentanan."""
        console.print(Panel(
            "[bold #FF1493]Network Security Audit[/]\n\n"
            "WiMO akan memeriksa beberapa aspek keamanan jaringan.",
            border_style=Pink.MAGENTA))

        if not self.hosts:
            console.print(f"\n[{Pink.WARN}]Belum scan. Jalankan 'scan' dulu.[/]")
            return

        # 1. Client isolation
        console.print(f"\n[{Pink.HOT}]1. Client Isolation Check[/]")
        routers = [h for h in self.hosts
                   if "Router" in h.get("type", "") or "Router" in h.get("vendor", "")]
        clients = [h for h in self.hosts if h not in routers]
        console.print(f"   Client terdeteksi : {len(clients)}")
        if len(clients) > 0:
            console.print(f"   [{Pink.OK}]Client isolation: TIDAK AKTIF[/]")
            console.print(f"   [{Pink.WARN}]   -> ARP spoof MUNGKIN bisa[/]")
        else:
            console.print(f"   [{Pink.OK}]Client isolation: AKTIF atau tidak ada client[/]")

        # 2. MAC randomization
        console.print(f"\n[{Pink.HOT}]2. MAC Randomization Check[/]")
        random_count = 0
        for h in self.hosts:
            mac = h.get("mac", "")
            prefix = mac.upper()[:2]
            try:
                first_byte = int(prefix, 16)
                if first_byte & 0x02:
                    random_count += 1
                    console.print(f"   [{Pink.WARN}]- {h['ip']} -> {mac} (random)[/]")
            except Exception:
                pass
        if random_count == 0:
            console.print(f"   [{Pink.OK}]Tidak ada MAC random[/]")
        else:
            console.print(f"   [{Pink.INFO}]Total {random_count} device pakai MAC random[/]")

        # 3. Info gateway
        console.print(f"\n[{Pink.HOT}]3. Gateway Info[/]")
        console.print(f"   Gateway  : {self.gateway}")
        console.print(f"   Interface: {self.iface}")

        # 4. Kesimpulan
        console.print(f"\n[{Pink.HOT}]4. Kesimpulan[/]")
        if len(clients) > 0 and random_count <= 1:
            console.print(f"   [{Pink.WARN}]Jaringan rentan ARP spoof[/]")
        elif random_count > 1:
            console.print(f"   [{Pink.WARN}]Sebagian rentan (banyak MAC random)[/]")
        else:
            console.print(f"   [{Pink.OK}]Jaringan punya proteksi dasar[/]")

    def cmd_report(self):
        """Buat laporan Markdown lengkap."""
        if not self.hosts:
            console.print(f"[{Pink.WARN}]Belum ada data. Jalankan 'scan' dulu.[/]")
            return
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        md_file = f"wimo_report_{ts}.md"
        html_file = f"wimo_report_{ts}.html"

        # Hitung statistik
        total = len(self.hosts)
        routers = [h for h in self.hosts
                   if "Router" in h.get("type", "") or "Router" in h.get("vendor", "")]
        clients = total - len(routers)

        # Markdown
        with open(md_file, "w") as f:
            f.write("# WiMO Network Audit Report\n\n")
            f.write(f"**Tanggal:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write(f"**Interface:** {self.iface}\n\n")
            f.write(f"**Gateway:** {self.gateway}\n\n")
            f.write("---\n\n")
            f.write("## Ringkasan\n\n")
            f.write(f"- Total device: **{total}**\n")
            f.write(f"- Router/AP: {len(routers)}\n")
            f.write(f"- Client: {clients}\n\n")
            f.write("## Daftar Device\n\n")
            f.write("| ID | IP | MAC | Nama | Vendor | Type |\n")
            f.write("|----|-----|-----|------|--------|------|\n")
            for h in self.hosts:
                name = h.get("alias", h.get("hostname", "-"))
                f.write(f"| {h['id']} | {h['ip']} | {h['mac']} | "
                       f"{name} | {h.get('vendor', '-')} | {h.get('type', '-')} |\n")
            f.write("\n---\n")
            f.write("*Generated by WiMO - Wireless Monitor & Orchestrator*\n")

        # HTML (dari Markdown sederhana)
        with open(html_file, "w") as f:
            f.write("<!DOCTYPE html><html><head><meta charset='utf-8'>\n")
            f.write("<title>WiMO Report</title>\n")
            f.write("<style>body{font-family:sans-serif;background:#1A0A12;color:#FFE4EC;")
            f.write("padding:20px}h1{color:#FF1493}h2{color:#FF69B4}")
            f.write("table{border-collapse:collapse;width:100%;margin:20px 0}")
            f.write("th{background:#2B0F1F;color:#FF69B4;padding:8px;text-align:left}")
            f.write("td{border-bottom:1px solid #8B5A6B;padding:6px}")
            f.write("tr:hover{background:#2B0F1F}</style></head><body>\n")
            f.write("<h1>WiMO Network Audit Report</h1>\n")
            f.write(f"<p><b>Tanggal:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>\n")
            f.write(f"<p><b>Interface:</b> {self.iface}</p>\n")
            f.write(f"<p><b>Gateway:</b> {self.gateway}</p>\n")
            f.write(f"<h2>Ringkasan</h2>\n")
            f.write(f"<ul><li>Total device: <b>{total}</b></li>")
            f.write(f"<li>Router/AP: {len(routers)}</li>")
            f.write(f"<li>Client: {clients}</li></ul>\n")
            f.write("<h2>Daftar Device</h2>\n")
            f.write("<table><tr><th>ID</th><th>IP</th><th>MAC</th>")
            f.write("<th>Nama</th><th>Vendor</th><th>Type</th></tr>\n")
            for h in self.hosts:
                name = h.get("alias", h.get("hostname", "-"))
                f.write(f"<tr><td>{h['id']}</td><td>{h['ip']}</td>")
                f.write(f"<td>{h['mac']}</td><td>{name}</td>")
                f.write(f"<td>{h.get('vendor', '-')}</td>")
                f.write(f"<td>{h.get('type', '-')}</td></tr>\n")
            f.write("</table></body></html>\n")

        console.print(f"[{Pink.OK}]v Laporan disimpan:[/]")
        console.print(f"   [{Pink.INFO}]{md_file}[/]")
        console.print(f"   [{Pink.INFO}]{html_file}[/]")

    def cmd_export(self):
        """Export device ke CSV."""
        if not self.hosts:
            console.print(f"[{Pink.WARN}]Belum ada data. Jalankan 'scan' dulu.[/]")
            return
        import csv
        from datetime import datetime
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = f"wimo_devices_{ts}.csv"
        with open(csv_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ID", "IP", "MAC", "Hostname", "Alias", "Vendor",
                       "Type", "Status", "Rate"])
            for h in self.hosts:
                w.writerow([h["id"], h["ip"], h["mac"],
                           h.get("hostname", "-"), h.get("alias", "-"),
                           h.get("vendor", "-"), h.get("type", "-"),
                           h.get("status", "-"), h.get("rate", "-")])
        console.print(f"[{Pink.OK}]v CSV disimpan:[/]")
        console.print(f"   [{Pink.INFO}]{csv_file}[/]")

    def cmd_free(self, hid):
        h = self._get_host(hid)
        if not h:
            console.print(f"[{Pink.ERROR}]ID {hid} tidak ditemukan.[/]")
            return
        if self.traffic:
            self.traffic.free(h["ip"])
        if self.arp:
            self.arp.restore(h["ip"], self.gateway)
        h["status"] = "free"
        h["rate"] = "-"
        console.print(f"[{Pink.OK}]Bebaskan {h['ip']}[/]")

    def cmd_info(self, hid):
        h = self._get_host(hid)
        if not h:
            console.print(f"[{Pink.ERROR}]ID {hid} tidak ditemukan.[/]")
            return
        body = (
            f"[{Pink.HOT}]IP       :[/] {h['ip']}\n"
            f"[{Pink.HOT}]MAC      :[/] {h['mac']}\n"
            f"[{Pink.HOT}]Hostname :[/] {h['hostname']}\n"
            f"[{Pink.HOT}]Vendor   :[/] {h['vendor']}\n"
            f"[{Pink.HOT}]Type     :[/] {h['type']}\n"
            f"[{Pink.HOT}]Status   :[/] {h['status']}\n"
            f"[{Pink.HOT}]Rate     :[/] {h['rate']}"
        )
        console.print(Panel(body,
                            title=f"[bold {Pink.MAGENTA}]Device #{hid}[/]",
                            border_style=Pink.ROSE))

    def cmd_monitor(self):
        if not self.hosts:
            console.print(f"[{Pink.WARN}]Belum ada data. Jalankan 'scan' dulu.[/]")
            return
        monitor = self._init_monitor()
        monitor.start()
        ip_to_id = {h["ip"]: h["id"] for h in self.hosts}
        try:
            with Live(console=console, refresh_per_second=2) as live:
                while True:
                    snap = monitor.snapshot()
                    tbl = Table(
                        title=f"[bold {Pink.HOT}]Live Monitor[/]",
                        border_style=Pink.ROSE,
                        header_style=f"bold {Pink.HOT}",
                    )
                    tbl.add_column("ID", justify="center", style=Pink.BLUSH)
                    tbl.add_column("IP", style=Pink.INFO)
                    tbl.add_column("RX kbit/s", justify="right", style=Pink.FUCHSIA)
                    tbl.add_column("TX kbit/s", justify="right", style=Pink.MAGENTA)
                    for ip, d in snap.items():
                        hid = ip_to_id.get(ip, "-")
                        tbl.add_row(str(hid), ip,
                                    f"{d['rx_kbps']:.1f}", f"{d['tx_kbps']:.1f}")
                    live.update(tbl)
                    time.sleep(0.5)
        except KeyboardInterrupt:
            monitor.stop()
            console.print(f"\n[{Pink.OK}]Monitor dihentikan.[/]")

    @staticmethod
    def _parse_rate(rate):
        rate = rate.strip().lower()
        mult = 1
        if rate.endswith("mbit"):
            mult, rate = 1000, rate[:-4]
        elif rate.endswith("kbit"):
            rate = rate[:-4]
        elif rate.endswith("m"):
            mult, rate = 1000, rate[:-1]
        elif rate.endswith("k"):
            rate = rate[:-1]
        return int(float(rate) * mult)

    def run(self):
        console.print()
        show_banner(console)
        console.print(f"[{Pink.INFO}]Interface :[/] [{Pink.HOT}]{self.iface or 'TIDAK TERDETEKSI'}[/]")
        console.print(f"[{Pink.INFO}]Gateway   :[/] [{Pink.HOT}]{self.gateway or 'TIDAK TERDETEKSI'}[/]")
        console.print(f"[{Pink.DIM}]Ketik 'help' untuk daftar perintah.[/]\n")

        if not self.iface:
            console.print(f"[{Pink.ERROR}]Interface tidak terdeteksi.[/]")
            return

        try:
            while True:
                try:
                    cmd = Prompt.ask(
                        f"[bold {Pink.HOT}]WiMO[/] [{Pink.ROSE}]>[/]"
                    ).strip()
                except (EOFError, KeyboardInterrupt):
                    break
                if not cmd:
                    continue
                parts = cmd.split()
                op = parts[0].lower()
                if op in ("quit", "exit"):
                    break
                elif op == "help":
                    console.print(Panel(HELP_TEXT, border_style=Pink.ROSE))
                elif op == "scan":
                    self.cmd_scan()
                elif op == "hosts":
                    self.cmd_hosts()
                elif op == "limit" and len(parts) == 3:
                    try:
                        self.cmd_limit(int(parts[1]), parts[2])
                    except ValueError:
                        console.print(f"[{Pink.ERROR}]Format: limit <id> <rate>[/]")
                elif op == "block" and len(parts) == 2:
                    try:
                        self.cmd_block(int(parts[1]))
                    except ValueError:
                        console.print(f"[{Pink.ERROR}]Format: block <id>[/]")
                elif op == "blockall":
                    self.cmd_blockall()
                elif op == "freeall":
                    self.cmd_freeall()
                elif op == "free" and len(parts) == 2:
                    try:
                        self.cmd_free(int(parts[1]))
                    except ValueError:
                        console.print(f"[{Pink.ERROR}]Format: free <id>[/]")
                elif op == "info" and len(parts) == 2:
                    try:
                        self.cmd_info(int(parts[1]))
                    except ValueError:
                        console.print(f"[{Pink.ERROR}]Format: info <id>[/]")
                elif op == "alias" and len(parts) >= 3:
                    try:
                        self.cmd_alias(int(parts[1]), " ".join(parts[2:]))
                    except ValueError:
                        console.print(f"[{Pink.ERROR}]Format: alias <id> <nama>[/]")
                elif op == "ping" and len(parts) == 2:
                    try:
                        self.cmd_ping(int(parts[1]))
                    except ValueError:
                        console.print(f"[{Pink.ERROR}]Format: ping <id>[/]")
                elif op == "stats":
                    self.cmd_stats()
                elif op == "audit":
                    self.cmd_audit()
                elif op == "watchdog":
                    self.cmd_watchdog()
                elif op == "report":
                    self.cmd_report()
                elif op == "export":
                    self.cmd_export()
                elif op == "monitor":
                    self.cmd_monitor()
                else:
                    console.print(f"[{Pink.ERROR}]Perintah tidak dikenali. Ketik 'help'.[/]")
        finally:
            console.print(f"\n[{Pink.WARN}]Membersihkan aturan & restore ARP...[/]")
            if self.arp:
                try:
                    self.arp.stop_all(self.gateway)
                except Exception:
                    pass
            if self.traffic:
                try:
                    self.traffic.cleanup()
                except Exception:
                    pass
            console.print(f"[{Pink.OK}]Selesai. Sampai jumpa![/]")
