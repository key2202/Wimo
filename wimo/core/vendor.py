"""Deteksi merek/vendor device dari MAC + hostname (fallback-safe, no network)."""
import re

try:
    from mac_vendor_lookup import MacLookup, VendorNotFoundError
    _HAS_LOOKUP = True
except ImportError:
    _HAS_LOOKUP = False
    VendorNotFoundError = Exception

FALLBACK_OUI = {
    "00:1A:11": "Google", "00:1B:63": "Apple", "00:1E:C2": "Apple",
    "00:1F:5B": "Apple", "00:21:E9": "Apple", "00:23:DF": "Apple",
    "00:25:00": "Apple", "00:26:BB": "Apple", "3C:5A:B4": "Google",
    "3C:07:54": "Apple", "40:6C:8F": "Apple", "44:D8:84": "Apple",
    "5C:95:AE": "Apple", "6C:40:08": "Apple", "7C:D1:C3": "Apple",
    "8C:85:90": "Apple", "9C:04:EB": "Apple", "A4:5E:60": "Apple",
    "AC:BC:32": "Apple", "B8:17:C2": "Apple", "BC:92:6B": "Apple",
    "D0:81:7A": "Apple", "DC:A9:04": "Apple", "F0:18:98": "Apple",
    "F0:DB:E2": "Apple", "00:1E:64": "Apple", "00:16:CB": "Apple",
    "00:03:93": "Apple", "00:0A:95": "Apple", "00:0D:93": "Apple",
    "00:12:FB": "Samsung", "00:15:99": "Samsung", "00:16:32": "Samsung",
    "00:1A:8A": "Samsung", "08:37:3D": "Samsung", "28:39:5E": "Samsung",
    "34:23:BA": "Samsung", "38:AA:3C": "Samsung", "5C:0A:5B": "Samsung",
    "00:9E:C8": "Xiaomi", "04:CF:8C": "Xiaomi", "0C:1D:AF": "Xiaomi",
    "28:6C:07": "Xiaomi", "34:80:B3": "Xiaomi", "50:8F:4C": "Xiaomi",
    "64:09:80": "Xiaomi", "78:11:DC": "Xiaomi", "F0:B4:29": "Xiaomi",
    "00:1D:0F": "TP-Link", "14:CC:20": "TP-Link", "50:C7:BF": "TP-Link",
    "A4:2B:B0": "TP-Link",
    "24:0A:C4": "Espressif", "30:AE:A4": "Espressif", "3C:71:BF": "Espressif",
    "84:CC:A8": "Espressif", "A4:CF:12": "Espressif",
    "B8:27:EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
    "00:1B:21": "Intel", "3C:97:0E": "Intel", "A4:34:D9": "Intel",
    "00:E0:4C": "Realtek", "52:54:00": "Realtek/QEMU",
    # Router umum di Indonesia (dari data ARP kamu)
    "04:F4:1C": "Router (Fiberhome?)",
    "C0:E4:34": "Router (ZTE?)",
    "24:FD:52": "Router (ZTE?)",
    "28:D0:43": "Xiaomi/POCO",
    "2C:3B:70": "Xiaomi/POCO",
    "B4:B5:B6": "Xiaomi/POCO",
    "70:66:55": "Huawei/China Mobile",
    "40:A3:CC": "Intel/OEM",
}


class VendorDetector:
    def __init__(self):
        # JANGAN panggil update_vendors() — itu yang bikin hang!
        self.lookup = None
        if _HAS_LOOKUP:
            try:
                self.lookup = MacLookup()
            except Exception:
                self.lookup = None

    HOSTNAME_HINTS = {
        r"iphone|ipad|ipod":         "Apple",
        r"macbook|imac|mac-mini":    "Apple",
        r"apple-?tv|appletv":        "Apple",
        r"galaxy|samsung|sm-":       "Samsung",
        r"redmi|xiaomi|mi-|poco":    "Xiaomi",
        r"oppo|cp[h]?\d+":           "Oppo",
        r"vivo|v\d{4}":              "Vivo",
        r"realme|rmx\d+":            "Realme",
        r"huawei|honor":             "Huawei",
        r"oneplus|one-?plus":        "OnePlus",
        r"pixel":                    "Google",
        r"lenovo|thinkpad":          "Lenovo",
        r"hp-|hewlett":              "HP",
        r"dell":                     "Dell",
        r"asus|zenbook|rog":         "Asus",
        r"acer|aspire":              "Acer",
        r"toshiba":                  "Toshiba",
        r"sony|bravia|playstation":  "Sony",
        r"lg-|lge":                  "LG",
        r"nintendo|switch":          "Nintendo",
        r"raspberry|rpi":            "Raspberry Pi",
        r"esp-|espressif":           "Espressif (IoT)",
        r"tp-?link|tplink":          "TP-Link",
        r"router|gateway|ap-":       "Router/AP",
        r"printer|hp-print":         "Printer",
        r"chromecast|google-?home":  "Google",
        r"amazon|echo|kindle|fire":  "Amazon",
    }

    TYPE_HINTS = {
        r"iphone|galaxy s|pixel \d|redmi note|poco":  "Smartphone",
        r"ipad|tab|galaxy tab":                        "Tablet",
        r"macbook|laptop|thinkpad|zenbook|aspire":     "Laptop",
        r"desktop|pc-|workstation":                    "Desktop",
        r"tv|bravia|smart-?tv|chromecast|appletv":     "Smart TV",
        r"printer|hp-print|canon|epson":               "Printer",
        r"router|gateway|ap-|access-?point":           "Router/AP",
        r"raspberry|esp-|arduino|iot":                 "IoT Device",
        r"playstation|xbox|switch":                    "Console",
        r"watch|band":                                 "Wearable",
    }

    def _fallback_mac(self, mac):
        prefix = mac.upper()[:8]
        return FALLBACK_OUI.get(prefix, "Unknown")

    def vendor_from_mac(self, mac):
        # Pakai lookup lokal (tanpa network)
        if self.lookup:
            try:
                return self.lookup.lookup(mac)
            except Exception:
                pass
        return self._fallback_mac(mac)

    def vendor_from_hostname(self, hostname):
        if not hostname:
            return None
        h = hostname.lower()
        for pattern, brand in self.HOSTNAME_HINTS.items():
            if re.search(pattern, h):
                return brand
        return None

    def device_type(self, hostname, vendor):
        h = (hostname or "").lower()
        for pattern, dtype in self.TYPE_HINTS.items():
            if re.search(pattern, h):
                return dtype
        v = (vendor or "").lower()
        if "apple" in v:      return "Apple Device"
        if "samsung" in v:    return "Samsung Device"
        if "xiaomi" in v or "poco" in v:  return "Xiaomi Device"
        if "tp-link" in v:    return "Network Gear"
        if "espressif" in v:  return "IoT Device"
        if "raspberry" in v:  return "Raspberry Pi"
        if "router" in v:     return "Router/AP"
        if "intel" in v or "realtek" in v: return "Computer"
        return "Unknown"

    def detect(self, mac, hostname=""):
        mac_vendor = self.vendor_from_mac(mac)
        host_vendor = self.vendor_from_hostname(hostname)
        vendor = host_vendor or mac_vendor or "Unknown"
        return {
            "vendor": vendor,
            "mac_vendor": mac_vendor,
            "type": self.device_type(hostname, vendor),
        }
