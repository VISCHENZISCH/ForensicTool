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

class ChromiumParser:
    def __init__(self, db_path: str):
        self.db_path = db_path

    def extract_history(self) -> Result[list[dict], str]:
        return Ok([{"url": "https://example.com", "visits": 5}])
