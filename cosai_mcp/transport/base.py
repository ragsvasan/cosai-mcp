"""Transport ABC — all transports implement this interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Transport(ABC):
    @abstractmethod
    async def connect(self) -> None: ...

    @abstractmethod
    async def send(self, method: str, params: dict[str, Any]) -> dict[str, Any]: ...

    @abstractmethod
    async def recv(self) -> dict[str, Any]: ...

    @abstractmethod
    async def close(self) -> None: ...

    async def __aenter__(self) -> "Transport":
        await self.connect()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()
