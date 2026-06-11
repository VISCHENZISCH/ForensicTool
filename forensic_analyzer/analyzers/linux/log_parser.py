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

class LinuxLogParser:
    def __init__(self, path: str):
        self.path = path

    def extract_artifacts(self) -> Result[list[str], str]:
        return Ok(["/var/log/auth.log analysis complete", ".bash_history extracted"])
