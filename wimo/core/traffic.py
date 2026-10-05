"""Traffic shaping via tc + iptables."""
import subprocess

class TrafficController:
    def __init__(self, interface: str):
        self.iface = interface
        self._next_class = 10
        self._host_class = {}
        self._init_qdisc()

    def _run(self, *args, check=False):
        return subprocess.run(args, capture_output=True, text=True, check=check)

    def _init_qdisc(self):
        self._run("tc", "qdisc", "del", "dev", self.iface, "root")
        self._run("tc", "qdisc", "add", "dev", self.iface,
                  "root", "handle", "1:", "htb", "default", "30")
        self._run("tc", "class", "add", "dev", self.iface,
                  "parent", "1:", "classid", "1:1", "htb", "rate", "1000mbit")
        self._run("tc", "class", "add", "dev", self.iface,
                  "parent", "1:1", "classid", "1:30", "htb", "rate", "1000mbit")

    def limit(self, ip: str, rate_kbit: int) -> bool:
        cls = self._host_class.get(ip)
        if cls is None:
            cls = self._next_class
            self._next_class += 1
            self._host_class[ip] = cls
            self._run("tc", "class", "add", "dev", self.iface,
                      "parent", "1:1", "classid", f"1:{cls}",
                      "htb", "rate", f"{rate_kbit}kbit", "ceil", f"{rate_kbit}kbit")
            self._run("tc", "filter", "add", "dev", self.iface,
                      "protocol", "ip", "parent", "1:", "prio", "1",
                      "u32", "match", "ip", "dst", ip, "flowid", f"1:{cls}")
        else:
            self._run("tc", "class", "change", "dev", self.iface,
                      "classid", f"1:{cls}", "htb", "rate",
                      f"{rate_kbit}kbit", "ceil", f"{rate_kbit}kbit")
        return True

    def block(self, ip: str):
        self._run("iptables", "-I", "FORWARD", "-s", ip, "-j", "DROP")
        self._run("iptables", "-I", "FORWARD", "-d", ip, "-j", "DROP")

    def unblock(self, ip: str):
        self._run("iptables", "-D", "FORWARD", "-s", ip, "-j", "DROP")
        self._run("iptables", "-D", "FORWARD", "-d", ip, "-j", "DROP")

    def free(self, ip: str):
        self.unblock(ip)
        cls = self._host_class.pop(ip, None)
        if cls:
            self._run("tc", "filter", "del", "dev", self.iface, "parent", "1:", "prio", "1")
            self._run("tc", "class", "del", "dev", self.iface, "classid", f"1:{cls}")

    def cleanup(self):
        for ip in list(self._host_class.keys()):
            self.unblock(ip)
        self._run("tc", "qdisc", "del", "dev", self.iface, "root")
