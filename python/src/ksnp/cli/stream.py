from enum import Enum
from sys import stdout, stderr
from uuid import UUID
import argparse
import socket

from . import EventLoop
from ..stream import OpenParams
from ..client import Client, event as client_event


class ClientState(Enum):
    PreHandshake = 1
    Ready = 2
    StreamOpen = 3


class StreamClient(EventLoop[Client]):
    def __init__(self, sock: socket.socket):
        super().__init__(Client, sock)
        self._state = ClientState.PreHandshake

    def _complete_handshake(self):
        event = self.wait_event()
        if not isinstance(event, client_event.Handshake):
            raise RuntimeError(f"Handshake failed {event}")
        self._state = ClientState.Ready

    def open_stream(self, destination: str, stream_id: UUID | None):
        match self._state:
            case ClientState.PreHandshake:
                self._complete_handshake()
            case ClientState.StreamOpen:
                raise RuntimeError("stream already open")
            case ClientState.Ready:
                pass

        self._handle.open_stream(
            OpenParams(
                destination=destination,
                stream_id=stream_id,
                chunk_size=32,
                min_bps=32,
            )
        )

        match self.wait_event():
            case client_event.StreamAccepted():
                self._state = ClientState.StreamOpen
            case client_event.StreamRejected(
                code=code, parameters=parameters, message=message
            ):
                print(
                    f"The server did not want to play ball: {code} {parameters} - {message}"
                )
                raise RuntimeError("failed to open stream")
            case e:
                raise RuntimeError(f"unexpected event {e}")

    def close_stream(self) -> None:
        if self._state != ClientState.StreamOpen:
            raise RuntimeError("no open stream")
        self._handle.close_stream()

        match self.wait_event():
            case client_event.StreamClose():
                self._state = ClientState.Ready
            case e:
                raise RuntimeError(f"unexpected event {e}")

    def stop(self):
        super().stop()
        while self.wait_event() is not None:
            pass

    def get_key(self) -> bytes | None:
        if self._state != ClientState.StreamOpen:
            raise RuntimeError("no open stream")

        self._handle.add_capacity(32)
        match self.wait_event():
            case client_event.KeyData(key_data=key_data):
                return key_data
            case client_event.StreamClose() | client_event.StreamSuspend():
                self._state = ClientState.Ready
                return None
            case client_event.Error(code=code, description=description):
                print(f"Failed to open stream: {code} - {description}", file=stderr)
                raise RuntimeError("Server error")
            case e:
                raise RuntimeError(f"unexpected event {e}")


def main():
    parser = argparse.ArgumentParser(description="Simple KSNP client")
    parser.add_argument(
        "host",
        help="Host to connect to",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to connect to",
    )
    parser.add_argument(
        "sae_id",
        help="SAE ID of remote entity",
    )
    parser.add_argument(
        "--stream-id",
        help="Stream ID",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=20,
        help="Keys to fetch",
    )

    args = parser.parse_args()

    addr = (args.host, args.port)
    stream_id = UUID(args.stream_id) if args.stream_id else None

    sock = socket.create_connection(addr)
    client = StreamClient(sock)

    try:
        client.open_stream(args.sae_id, stream_id)

        for _ in range(args.count):
            key_data = client.get_key()
            if key_data is None:
                break
            stdout.write(key_data.hex())
        stdout.write("\n")
    except KeyboardInterrupt:
        pass

    client.close_stream()
    client.stop()
