"""Détection du type de fichier via Magic Bytes (En-têtes)."""
import os

def get_file_magic_extension(filepath: str) -> str:
    """Renvoie une pseudo-extension (.pdf, .exe) basée sur les magic bytes du fichier."""
    if not os.path.isfile(filepath):
        return ""
        
    try:
        with open(filepath, 'rb') as f:
            header = f.read(16)
            
        if not header:
            return ""
            
        # Exécutable Windows (PE / MZ)
        if header.startswith(b'MZ'):
            return '.exe'
            
        # ELF Executable (Linux)
        if header.startswith(b'\x7FELF'):
            return '.elf'
            
        # PDF Document
        if header.startswith(b'%PDF'):
            return '.pdf'
            
        # Archive ZIP / DOCX / XLSX / JAR
        if header.startswith(b'PK\x03\x04'):
            return '.zip'
            
        # PCAP (Magic number: A1 B2 C3 D4 ou D4 C3 B2 A1)
        if header.startswith(b'\xa1\xb2\xc3\xd4') or header.startswith(b'\xd4\xc3\xb2\xa1'):
            return '.pcap'
            
        # PCAPNG (Magic number: 0A 0D 0D 0A)
        if header.startswith(b'\x0a\x0d\x0d\x0a'):
            return '.pcapng'
            
        # SQLite Database (Historique Navigateurs, Cookies)
        if header.startswith(b'SQLite format 3\x00'):
            return '.sqlite'
            
        # JPEG Image
        if header.startswith(b'\xFF\xD8\xFF'):
            return '.jpg'
            
        # PNG Image
        if header.startswith(b'\x89PNG\r\n\x1A\n'):
            return '.png'
            
        # MSI Installer / OLE2 (Composite Document File V2)
        if header.startswith(b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1'):
            return '.msi'
            
        # Script Bash / Shebang
        if header.startswith(b'#!'):
            return '.sh'

    except Exception as exc:
        pass  # TODO: log.debug(exc)
        pass
        
    return ""
