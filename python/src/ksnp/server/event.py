from .._core.server.event import *  # noqa: F403

type Event = (
    Handshake
    | OpenStream
    | CloseStream
    | SuspendStream
    | KeepAlive
    | NewCapacity
    | Error
)
