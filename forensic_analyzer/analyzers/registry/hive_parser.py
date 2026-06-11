from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar('T')
E = TypeVar('E')

@dataclass(frozen=True)
class Ok(Generic[T]):
    value: T
    ok: bool = True

@dataclass(frozen=True)
class Err(Generic[E]):
    error: E
    ok: bool = False

Result = Ok[T] | Err[E]

class RegistryHiveParser:
    def __init__(self, path: str):
        self.path = path
        
    def extract_keys(self) -> Result[list[str], str]:
        try:
            # Simulate registry parsing
            return Ok(["HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"])
        except Exception as e:
            return Err(str(e))
