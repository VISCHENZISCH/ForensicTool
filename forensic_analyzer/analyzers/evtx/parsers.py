from dataclasses import dataclass, field
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

@dataclass(slots=True)
class WindowsEvent:
    event_id: int
    timestamp: str
    data: dict

@dataclass
class EVTXParseResult:
    critical_events: list[WindowsEvent] = field(default_factory=list)

class EVTXParser:
    """Analyseur avancé EVTX."""
    def __init__(self, filepath: str):
        self.filepath = filepath

    def parse(self) -> Result[EVTXParseResult, str]:
        try:
            # Simulation of evtx parsing logic
            events = [
                WindowsEvent(4624, "2023-01-01T12:00:00Z", {"user": "admin"}),
                WindowsEvent(4625, "2023-01-01T12:05:00Z", {"user": "guest"}),
            ]
            return Ok(EVTXParseResult(critical_events=events))
        except Exception as e:
            return Err(str(e))
