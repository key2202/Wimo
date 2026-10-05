"""Banner ASCII bertema pink."""
from rich.console import Console
from rich.text import Text
from rich.align import Align
from .theme import Pink

BANNER = r"""
 ██╗    ██╗ ██╗ ███╗   ███╗  ██████╗
 ██║    ██║ ██║ ████╗ ████║ ██╔═══██╗
 ██║ █╗ ██║ ██║ ██╔████╔██║ ██║   ██║
 ██║███╗██║ ██║ ██║╚██╔╝██║ ██║   ██║
 ╚███╔███╔╝ ██║ ██║ ╚═╝ ██║ ╚██████╔╝
  ╚══╝╚══╝  ╚═╝ ╚═╝     ╚═╝  ╚═════╝
"""

SUBTITLE = "Wireless Monitor & Orchestrator  •  v1.0.0"

def show_banner(console: Console):
    text = Text(BANNER, style=f"bold {Pink.HOT}")
    sub  = Text(SUBTITLE, style=f"italic {Pink.BLUSH}", justify="center")
    console.print(Align.center(text))
    console.print(Align.center(sub))
    console.print(Align.center(Text("─" * 55, style=Pink.DIM)))
    console.print()
