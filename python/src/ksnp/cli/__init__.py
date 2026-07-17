from collections.abc import Buffer
from enum import Enum
from io import FileIO
from socket import SHUT_WR
from typing import Protocol, Self, cast, overload
import selectors

from .. import CloseDirection
from ..client import Client
from ..client.event import Event as ClientEvent
from ..server import Server
from ..server.event import Event as ServerEvent


class EventState(Enum):
    PreHandshake = 1
    Ready = 2
    StreamOpen = 3


class SocketLike(Protocol):
    def recv(self, bufsize: int, flags: int = 0, /) -> bytes: ...

    def send(self, data: Buffer, flags: int = 0, /) -> int: ...

    def shutdown(self, how: int, /) -> None: ...

    def fileno(self) -> int: ...


class EventLoop[T: Client | Server]:
    def __init__(self: Self, handle: type[T], sock: SocketLike):
        self._sock = sock
        self._read_buf = bytearray()
        self._write_buf = bytearray()
        # Use cast to ignore mypy. Ignore pylance warnings.
        self._handle: T = cast("T", handle(self._read_buf, self._write_buf))  # type: ignore
        self._stopped = False

    def stop(self) -> None:
        if not self._stopped:
            self._handle.close_connection(CloseDirection.WRITE)
            self._stopped = True

    @overload
    def wait_event(
        self: "EventLoop[Client]",
        stop_event: FileIO | None = None,
        timeout: float | None = None,
    ) -> ClientEvent | None: ...

    @overload
    def wait_event(
        self: "EventLoop[Server]",
        stop_event: FileIO | None = None,
        timeout: float | None = None,
    ) -> ServerEvent | None: ...

    def wait_event(
        self, stop_event: FileIO | None = None, timeout: float | None = None
    ) -> ClientEvent | ServerEvent | None:
        with selectors.DefaultSelector() as sel:
            sel.register(self._sock, selectors.EVENT_READ)
            if stop_event is not None and not self._stopped:
                sel.register(stop_event, selectors.EVENT_READ)

            while (next_event := self._handle.next_event()) is None:
                if not self._handle.want_read() and not self._handle.want_write():
                    return None

                if self._handle.want_write():
                    self._handle.flush_data()
                    if len(self._write_buf) == 0:
                        self._sock.shutdown(SHUT_WR)

                mask = 0
                if self._handle.want_read():
                    mask |= selectors.EVENT_READ
                if len(self._write_buf) > 0:
                    mask |= selectors.EVENT_WRITE
                sel.modify(self._sock, mask)

                events = sel.select(timeout=timeout)
                if len(events) == 0:
                    raise TimeoutError

                for obj, mask in events:
                    if obj.fileobj == stop_event:
                        self.stop()

                    if obj.fileobj == self._sock:
                        if mask & selectors.EVENT_READ:
                            try:
                                data = self._sock.recv(4096)
                            except IOError:
                                return None
                            if len(data) == 0:
                                self._handle.close_connection(CloseDirection.READ)
                            else:
                                self._read_buf.extend(data)

                        if mask & selectors.EVENT_WRITE:
                            try:
                                count = self._sock.send(self._write_buf)
                            except IOError:
                                return None
                            del self._write_buf[:count]
        return next_event
