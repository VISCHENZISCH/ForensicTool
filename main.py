#!/usr/bin/env python3
# coding:utf8

import os
import sys

# --- Forensic Dependencies (Modern & Fast) ---
try:
    from pypdf import PdfReader
except ImportError:
    PdfReader = None

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
except ImportError:
    Image = None

# --- UI & Performance Feedback (Rich Integration) ---
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.status import Status
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

# Console Color Emulation Layer (as requested)
class ConsoleColor:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

class ForensicAnalyzer:
    def __init__(self):
        self.console = Console() if HAS_RICH else None
        self.cc = ConsoleColor()

    def print_banner(self):
        title = "FORENSIC ANALYZER"
        if HAS_RICH:
            # Get terminal width to avoid overflowing smaller windows
            c_width = min(self.console.width, 64)
            self.console.print(Panel(
                Text(title, style="bold white on blue", justify="center"),
                subtitle=" PDF & Image Meta-Analysis",
                border_style="bright_blue",
                width=c_width
            ))
        else:
            print(f"{self.cc.BLUE}{self.cc.BOLD}{'='*60}")
            print(f"  {title}")
            print(f"{'='*60}{self.cc.RESET}")

    def analyze_pdf(self, path):
        """Extracts high-level and forensic metadata from PDFs."""
        if not PdfReader:
            print(f"{self.cc.RED}[-] Missing 'pypdf' library. Please run: pip install pypdf{self.cc.RESET}")
            return

        try:
            reader = PdfReader(path)
            meta = reader.metadata
            
            if HAS_RICH:
                c_width = min(self.console.width, 64)
                table = Table(title=f"PDF Report: [cyan]{os.path.basename(path)}[/]", show_header=True, header_style="bold magenta", border_style="blue", width=c_width)
                table.add_column("Property", style="dim")
                table.add_column("Forensic Discovery", style="green")

                if meta:
                    for key, val in meta.items():
                        table.add_row(str(key), str(val))
                
                table.add_section()
                table.add_row("Page Count", str(len(reader.pages)))
                table.add_row("Encryption Status", "Encrypted" if reader.is_encrypted else "Unencrypted")
                table.add_row("PDF Version", str(reader.pdf_header))
                
                self.console.print("")  # Top margin
                self.console.print(table)
                self.console.print("")  # Bottom margin
            else:
                print(f"\n{self.cc.CYAN}[+] PDF Trace: {path}{self.cc.RESET}")
                if meta:
                    for k, v in meta.items(): print(f"  {k}: {v}")
                print(f"  Pages: {len(reader.pages)}")
        except Exception as e:
            print(f"{self.cc.RED}[!] PDF Error: {e}{self.cc.RESET}")

    def analyze_image(self, path):
        """Dives into EXIF data and Image characteristics."""
        if not Image:
            print(f"{self.cc.RED}[-] Missing 'Pillow' library. Please run: pip install Pillow{self.cc.RESET}")
            return

        try:
            with Image.open(path) as img:
                exif = img.getexif()
                
                if HAS_RICH:
                    c_width = min(self.console.width, 64)
                    table = Table(title=f"Image Trace: [cyan]{os.path.basename(path)}[/]", show_header=True, header_style="bold magenta", border_style="blue", width=c_width)
                    table.add_column("Exif Tag", style="dim")
                    table.add_column("Metadata Value", style="green")

                    table.add_row("Format", str(img.format))
                    table.add_row("Dimensions", f"{img.size[0]}x{img.size[1]}")

                    if exif:
                        for tag_id, value in exif.items():
                            tag = TAGS.get(tag_id, tag_id)
                            # Handle GPS separately or truncate long strings
                            val_str = str(value)
                            if len(val_str) > 60: val_str = val_str[:57] + "..."
                            table.add_row(str(tag), val_str)
                    else:
                        table.add_row("EXIF", "[yellow]No EXIF headers found[/]")
                    
                    self.console.print("")  # Top margin
                    self.console.print(table)
                    self.console.print("")  # Bottom margin
                else:
                    print(f"\n{self.cc.CYAN}[+] Image Trace: {path}{self.cc.RESET}")
                    print(f"  Format: {img.format}, Size: {img.size}")
        except Exception as e:
            print(f"{self.cc.RED}[!] Image Error: {e}{self.cc.RESET}")

    def run(self):
        self.print_banner()
        
        # Performance optimized path scanning
        files = [f for f in os.listdir('.') if os.path.isfile(f)]
        pdf_targets = [f for f in files if f.lower().endswith('.pdf')]
        img_targets = [f for f in files if f.lower().endswith(('.jpg', '.jpeg', '.png', '.tiff', '.bmp'))]

        if not pdf_targets and not img_targets:
            print(f"{self.cc.YELLOW}[*] No PDF/Images found in this sector.{self.cc.RESET}")
            return

        # Execute analysis with visual status
        if HAS_RICH:
            with Status("[bold yellow]Extracting metadata deep-strata...", console=self.console):
                for p in pdf_targets: self.analyze_pdf(p)
                for i in img_targets: self.analyze_image(i)
        else:
            for p in pdf_targets: self.analyze_pdf(p)
            for i in img_targets: self.analyze_image(i)

if __name__ == "__main__":
    try:
        ForensicAnalyzer().run()
    except KeyboardInterrupt:
        print("\n[!] Operation terminated.")
        sys.exit(0)