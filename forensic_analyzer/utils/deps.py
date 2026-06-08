"""
Gestion centralisée des dépendances optionnelles.
Tous les modules importent leurs dépendances depuis ce fichier unique.
"""

#PDF
try:
    from pypdf import PdfReader
    HAS_PYPDF = True
except ImportError:
    PdfReader = None
    HAS_PYPDF = False

#Image 
try:
    from PIL import Image as PILImage
    from PIL.ExifTags import TAGS as PIL_TAGS
    HAS_PIL = True
except ImportError:
    PILImage = None
    PIL_TAGS: dict = {}
    HAS_PIL = False

#EXIF / GPS 
try:
    import exifread
    HAS_EXIFREAD = True
except ImportError:
    exifread = None          # type: ignore[assignment]
    HAS_EXIFREAD = False

#Rich UI
try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    HAS_RICH = True
except ImportError:
    Console = Table = Panel = Text = box = None  # type: ignore[assignment,misc]
    HAS_RICH = False
