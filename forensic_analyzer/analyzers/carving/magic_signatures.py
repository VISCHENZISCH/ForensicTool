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

class MagicCarver:
    def __init__(self, filepath: str):
        self.filepath = filepath

    def carve(self) -> Result[list[str], str]:
        return Ok(["file1.jpg (FF D8 FF)", "file2.pdf (25 50 44 46)"])
