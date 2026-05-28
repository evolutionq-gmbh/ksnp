from enum import Enum
from io import FileIO
from socket import socket, SHUT_WR
from typing import Self, cast
import selectors

from .. import CloseDirection
from ..client import Client
from ..server import Server


class EventState(Enum):
    PreHandshake = 1
    Ready = 2
    StreamOpen = 3


class EventLoop[T: Client | Server]:
    def __init__(self: Self, handle: type[T], sock: socket):
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

    def wait_event(self, stop_event: FileIO | None = None):
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

                events = sel.select(timeout=None)
                if len(events) == 0:
                    return None

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
