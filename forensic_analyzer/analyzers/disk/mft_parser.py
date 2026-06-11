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

class MFTParser:
    def __init__(self, image_path: str):
        self.image_path = image_path

    def parse_mft(self) -> Result[list[dict], str]:
        # Advanced MFT parsing logic stub
        return Ok([{"filename": "$MFT", "size": 1024}])
