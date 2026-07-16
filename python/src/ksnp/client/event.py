from .._core.client.event import *  # noqa: F403

type Event = (
    Handshake
    | StreamAccepted
    | StreamRejected
    | StreamClose
    | StreamSuspend
    | KeyData
    | KeepAlive
    | Error
)
