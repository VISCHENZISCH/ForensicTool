import warnings

# scapy charge ses couches TLS (échange de clés FFDH) dès l'import ; les versions récentes de
# cryptography le signalent comme obsolète. Sans effet sur l'analyse : seul ce message est masqué.
warnings.filterwarnings("ignore", message="Diffie-Hellman over finite fields", module=r"scapy\.")

from .analyzer import PCAPAnalyzer  # noqa: E402

__all__ = ['PCAPAnalyzer']
