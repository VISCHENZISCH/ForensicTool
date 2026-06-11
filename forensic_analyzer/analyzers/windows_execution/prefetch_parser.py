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

class PrefetchLnkParser:
    def __init__(self, path: str):
        self.path = path

    def parse(self) -> Result[list[dict], str]:
        return Ok([{"type": "prefetch", "executable": "cmd.exe", "run_count": 12}])
