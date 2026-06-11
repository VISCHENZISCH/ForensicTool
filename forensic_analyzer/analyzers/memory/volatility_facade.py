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

class VolatilityFacade:
    def __init__(self, image_path: str, os_type: str):
        self.image_path = image_path
        self.os_type = os_type

    def run_plugins(self, plugins: list[str]) -> Result[dict, str]:
        return Ok({p: "Mock result for memory plugin" for p in plugins})
