from contextlib import ExitStack
from io import FileIO
from os import pipe
from random import Random
from typing import Any
from uuid import uuid4, UUID
from threading import Thread
import argparse
import socket


from . import EventLoop
from .. import StatusCode
from ..stream import AcceptedParams, Stream, QosParams
from ..server import Server, event as server_event


class UuidStream(Stream):
    def __init__(self, chunk_size: int, stream_id: UUID):
        super().__init__(chunk_size)
        self._rng = Random(stream_id.bytes)

    def has_chunk_available(self) -> bool:
        return True

    def next_chunk(self, max_count: int) -> memoryview[int]:
        count = self.chunk_size * max_count
        return memoryview(self._rng.randbytes(count))


class CliServer(EventLoop[Server]):
    def __init__(self, sock: socket.socket):
        super().__init__(Server, sock)

    def run(self, stop_event: FileIO) -> None:
        while (event := self.wait_event(stop_event)) is not None:
            match event:
                case server_event.Handshake():
                    pass
                case server_event.OpenStream(parameters=parameters):
                    if parameters.stream_id is None:
                        stream_id = uuid4()
                    else:
                        stream_id = parameters.stream_id
                    if parameters.chunk_size == 0:
                        chunk_size = 16
                    else:
                        chunk_size = parameters.chunk_size
                    failed = False
                    match parameters.min_bps:
                        case (bits, seconds):
                            if bits / seconds > 128:
                                failed = True
                        case int(bits):
                            if bits > 128:
                                failed = True
                        case None:
                            pass
                    if failed:
                        self._handle.open_stream_fail(
                            StatusCode.OPERATION_NOT_SUPPORTED,
                            QosParams(
                                min_bps=(1, 128),
                            ),
                            "BPS out of range",
                        )
                    else:
                        self._handle.open_stream_ok(
                            UuidStream(chunk_size, stream_id),
                            AcceptedParams(
                                min_bps=parameters.min_bps,
                                stream_id=stream_id
                                if parameters.stream_id is None
                                else None,
                                chunk_size=chunk_size,
                            ),
                        )
                case server_event.CloseStream():
                    pass
                case server_event.SuspendStream():
                    self._handle.suspend_stream_fail(
                        StatusCode.OPERATION_NOT_SUPPORTED, "not supported"
                    )
                case server_event.KeepAlive():
                    self._handle.keep_alive_fail(
                        StatusCode.OPERATION_NOT_SUPPORTED, "not supported"
                    )
                case server_event.NewCapacity():
                    pass
                case server_event.Error(code=code, description=description):
                    print(f"Client caused an error {code} {description}")


def serve(sock: socket.socket, addr: Any, stop_event: FileIO) -> None:
    with sock, stop_event:
        print(f"Serving connection from {addr}")
        CliServer(sock).run(stop_event)
    print(f"Connection from {addr} closed")


def main():
    parser = argparse.ArgumentParser(description="Simple KSNP server")
    parser.add_argument(
        "--interface",
        default="localhost",
        help="Interface/IP address to listen on",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Port to listen on",
    )

    args = parser.parse_args()

    addr = (args.interface, args.port)

    if socket.has_dualstack_ipv6():
        s = socket.create_server(addr, family=socket.AF_INET6, dualstack_ipv6=True)
    else:
        s = socket.create_server(addr)

    client_threads: list[Thread] = []
    try:
        with s as server, ExitStack() as stack:
            print(f"Listening on {args.interface}:{args.port}")

            while True:
                sock, addr = server.accept()
                (pipe_r, pipe_w) = pipe()
                (pipe_rf, pipe_wf) = (
                    open(pipe_r, "rb", buffering=0),
                    open(pipe_w, "wb", buffering=0),
                )
                stack.enter_context(pipe_wf)
                t = Thread(target=serve, args=(sock, addr, pipe_rf))
                t.start()
                client_threads.append(t)
    except KeyboardInterrupt:
        # Ignore Ctrl-C, allowed to stop the server
        pass
