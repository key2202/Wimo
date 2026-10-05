"""Tabel tampilan host dengan warna pink."""
from rich.table import Table
from rich.text import Text
from .theme import Pink

def hosts_table(hosts: list) -> Table:
    t = Table(
        title="[bold #FF1493]◈ Connected Devices ◈[/]",
        border_style=Pink.ROSE,
        header_style=f"bold {Pink.HOT}",
        title_style=f"bold {Pink.MAGENTA}",
        expand=True,
    )
    t.add_column("ID",       justify="center", style=Pink.BLUSH, width=4)
    t.add_column("IP",       style=Pink.INFO)
    t.add_column("MAC",      style=Pink.BLUSH)
    t.add_column("Hostname", style=Pink.TEXT, overflow="fold")
    t.add_column("Vendor",   style=Pink.ROSE)
    t.add_column("Type",     style=Pink.FUCHSIA)
    t.add_column("Status",   justify="center")
    t.add_column("Rate",     justify="right", style=Pink.INFO)

    status_color = {
        "free":    f"bold {Pink.OK}",
        "limited": f"bold {Pink.WARN}",
        "blocked": f"bold {Pink.ERROR}",
    }

    for h in hosts:
        st = h.get("status", "free")
        status = Text(st.upper(), style=status_color.get(st, Pink.DIM))
        t.add_row(
            str(h["id"]), h["ip"], h["mac"],
            h.get("hostname", "—"),
            h.get("vendor", "Unknown"),
            h.get("type", "❓"),
            status,
            h.get("rate", "—"),
        )
    return t
