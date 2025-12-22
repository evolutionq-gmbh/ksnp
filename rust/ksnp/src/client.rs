use core::{ffi::CStr, mem::MaybeUninit, num::NonZero, ptr::null_mut, slice, time::Duration};

use uuid::Uuid;

use crate::{
    message::MessageContext,
    processor::Processor,
    sys::{self, ksnp_error},
    types::{
        CloseDirection, StreamAcceptedParams, StreamOpenParams, StreamQosParams, map_err,
        string_ref,
    },
};

/// Wrapper for a [`sys::ksnp_client`].
pub struct ClientConnection {
    ctx: MessageContext,
    client: *mut sys::ksnp_client,
}

// SAFETY: The sys::ksnp_client can be moved across threads safely.
unsafe impl Send for ClientConnection {}

impl Drop for ClientConnection {
    fn drop(&mut self) {
        // SAFETY: self.client is valid for the lifetime of this wrapper.
        unsafe { sys::ksnp_client_destroy(self.client) };
    }
}

impl ClientConnection {
    /// Creates a new [`sys::ksnp_client`] wrapper with a new
    /// client_connection that uses the given [`MessageContext`].
    pub fn new(ctx: MessageContext) -> Option<Self> {
        let mut this = Self {
            ctx,
            client: null_mut(),
        };
        // SAFETY: client is a valid writeable pointer, and the message context
        // does not move its internal pointer.
        if unsafe { sys::ksnp_client_create(&raw mut this.client, this.ctx.ctx) }.0 != 0 {
            None
        } else {
            Some(this)
        }
    }

    pub fn open_stream(&mut self, parameters: &StreamOpenParams<'_>) -> Result<(), ksnp_error> {
        // SAFETY: The pointers in the parameters are only used for the duration
        // of this call.
        let parameters = unsafe { parameters.to_sys() };
        // SAFETY: client is a valid writeable pointer, and the parameters are
        // valid for the duration of this call.
        map_err(unsafe { sys::ksnp_client_open_stream(self.client, &raw const parameters) })?;
        Ok(())
    }

    pub fn close_stream(&mut self) -> Result<(), ksnp_error> {
        // SAFETY: client is a valid writeable pointer.
        map_err(unsafe { sys::ksnp_client_close_stream(self.client) })?;
        Ok(())
    }

    pub fn suspend_stream(&mut self, timeout: u32) -> Result<(), ksnp_error> {
        // SAFETY: client is a valid writeable pointer.
        map_err(unsafe { sys::ksnp_client_suspend_stream(self.client, timeout) })?;
        Ok(())
    }

    pub fn add_capacity(&mut self, additional_capacity: u32) -> Result<(), ksnp_error> {
        // SAFETY: client is a valid writeable pointer.
        map_err(unsafe { sys::ksnp_client_add_capacity(self.client, additional_capacity) })?;
        Ok(())
    }

    pub fn keep_alive(&mut self, stream_id: Uuid) -> Result<(), ksnp_error> {
        // SAFETY: client is a valid writeable pointer. The stream id provides a
        // valid array.
        map_err(unsafe { sys::ksnp_client_keep_alive(self.client, stream_id.as_bytes()) })?;
        Ok(())
    }

    pub fn close_connection(&mut self, dir: CloseDirection) -> Result<(), ksnp_error> {
        // SAFETY: client is a valid writeable pointer.
        map_err(unsafe { sys::ksnp_client_close_connection(self.client, dir.into()) })?;
        Ok(())
    }
}

impl Processor for ClientConnection {
    type Value<'a>
        = Option<ClientEvent<'a>>
    where
        Self: 'a;

    fn message_context(&self) -> &MessageContext {
        &self.ctx
    }

    fn message_context_mut(&mut self) -> &mut MessageContext {
        &mut self.ctx
    }

    fn want_read(&self) -> bool {
        // SAFETY: self.client is valid for the lifetime of this wrapper.
        unsafe { sys::ksnp_client_want_read(self.client) }
    }

    fn want_write(&self) -> bool {
        // SAFETY: self.client is valid for the lifetime of this wrapper.
        unsafe { sys::ksnp_client_want_write(self.client) }
    }

    fn read_data(&mut self, data: &[u8]) -> Result<usize, ksnp_error> {
        let mut len = data.len();
        // SAFETY: self.client is valid for the lifetime of this wrapper, the
        // buffer and size pointers are derived from valid instances, len is
        // initialized properly.
        map_err(unsafe { sys::ksnp_client_read_data(self.client, data.as_ptr(), &raw mut len) })?;
        Ok(len)
    }

    fn flush_data(&mut self) -> Result<(), ksnp_error> {
        // SAFETY: self.client is valid for the lifetime of this wrapper.
        map_err(unsafe { sys::ksnp_client_flush_data(self.client) })
    }

    fn write_data(&mut self, data: &mut [MaybeUninit<u8>]) -> Result<usize, ksnp_error> {
        let mut len = data.len();
        // SAFETY: self.client is valid for the lifetime of this wrapper, the
        // buffer and size pointers are derived from valid instances, len is
        // initialized properly.
        map_err(unsafe {
            sys::ksnp_client_write_data(self.client, data.as_mut_ptr().cast::<u8>(), &raw mut len)
        })?;
        Ok(len)
    }

    fn next_event(&mut self) -> Result<Self::Value<'_>, ksnp_error> {
        let mut event = MaybeUninit::uninit();
        // SAFETY: self.client is valid for the lifetime of this wrapper, the
        // event pointer is writeable.
        map_err(unsafe { sys::ksnp_client_next_event(self.client, event.as_mut_ptr()) })?;
        // SAFETY: On success the event is valid and assume_init can be called.
        // The event is valid for the current exclusive borrow of self, as it
        // prevents any other the other client methods from being called.
        Ok(unsafe { ClientEvent::from_event(event.assume_init()) })
    }
}

pub enum ClientEvent<'ctx> {
    Handshake {
        protocol: u8,
    },
    OpenStream {
        parameters: StreamAcceptedParams<'ctx>,
    },
    OpenStreamFailed {
        code: NonZero<u32>,
        parameters: Option<StreamQosParams<'ctx>>,
        message: Option<&'ctx CStr>,
    },
    CloseStream {
        code: u32,
        message: Option<&'ctx CStr>,
    },
    SuspendStream {
        timeout: Duration,
    },
    SuspendStreamFailed {
        code: NonZero<u32>,
        message: Option<&'ctx CStr>,
    },
    KeepAlive,
    KeepAliveFailed {
        code: NonZero<u32>,
        message: Option<&'ctx CStr>,
    },
    KeyData {
        key_data: &'ctx [u8],
    },
    Error {
        code: u32,
    },
}

impl ClientEvent<'_> {
    /// Converts a client event from a raw stream open event.
    ///
    /// # Safety
    ///
    /// The event must point to data that is valid for the lifetime of this
    /// client event.
    unsafe fn from_stream_open(value: sys::ksnp_client_event_stream_open) -> Self {
        match NonZero::new(value.code.0) {
            None => Self::OpenStream {
                // SAFETY: A message with status 0 has a valid reply object
                parameters: StreamAcceptedParams::from_accepted_params(unsafe {
                    value.parameters.reply.as_ref().unwrap()
                }),
            },
            Some(code) => Self::OpenStreamFailed {
                code,
                // SAFETY: A message with non-zero status has a no parameters or
                // a qos object.
                parameters: unsafe { value.parameters.qos.as_ref() }
                    .map(StreamQosParams::from_qos_params),
                // SAFETY: The message pointer is valid for the lifetime of the
                // event.
                message: unsafe { string_ref(value.message) },
            },
        }
    }

    /// Converts a client event from a raw stream close event.
    ///
    /// # Safety
    ///
    /// The event must point to data that is valid for the lifetime of this
    /// client event.
    unsafe fn from_stream_close(value: sys::ksnp_client_event_stream_close) -> Self {
        Self::CloseStream {
            code: value.code.0,
            // SAFETY: The message pointer is valid for the lifetime of the
            // event.
            message: unsafe { string_ref(value.message) },
        }
    }

    /// Converts a client event from a raw key data event.
    ///
    /// # Safety
    ///
    /// The event must point to data that is valid for the lifetime of this
    /// client event.
    fn from_key_data(value: sys::ksnp_client_event_key_data) -> Self {
        Self::KeyData {
            // SAFETY: The key data from a key data event points to a valid
            // buffer.
            key_data: unsafe { slice::from_raw_parts(value.key_data.data, value.key_data.len) },
        }
    }

    /// Converts a client event from a raw keep alive event.
    ///
    /// # Safety
    ///
    /// The event must point to data that is valid for the lifetime of this
    /// client event.
    unsafe fn from_keep_alive(value: sys::ksnp_client_event_keep_alive) -> Self {
        match NonZero::new(value.code.0) {
            None => Self::KeepAlive,
            Some(code) => Self::KeepAliveFailed {
                code,
                // SAFETY: The message pointer is valid for the lifetime of the
                // event.
                message: unsafe { string_ref(value.message) },
            },
        }
    }
}

impl From<sys::ksnp_client_event_handshake> for ClientEvent<'_> {
    fn from(value: sys::ksnp_client_event_handshake) -> Self {
        Self::Handshake {
            protocol: value.protocol.0,
        }
    }
}

impl From<sys::ksnp_client_event_stream_suspend> for ClientEvent<'_> {
    fn from(value: sys::ksnp_client_event_stream_suspend) -> Self {
        match NonZero::new(value.code.0) {
            None => Self::SuspendStream {
                timeout: Duration::from_secs(value.timeout.into()),
            },
            Some(code) => Self::SuspendStreamFailed {
                code,
                // SAFETY: The message pointer is valid for the lifetime of the
                // event.
                message: unsafe { string_ref(value.message) },
            },
        }
    }
}

impl From<sys::ksnp_client_event_error> for ClientEvent<'_> {
    fn from(value: sys::ksnp_client_event_error) -> Self {
        Self::Error { code: value.code.0 }
    }
}

impl ClientEvent<'_> {
    /// Converts a client event from a raw event.
    ///
    /// # Safety
    ///
    /// The event must point to data that is valid for the lifetime of this
    /// client event.
    pub unsafe fn from_event(value: sys::ksnp_client_event) -> Option<Self> {
        // SAFETY: The union's type dictates which field is set.
        let event = unsafe {
            match value.type_ {
                sys::ksnp_client_event_type::KSNP_CLIENT_EVENT_NONE => return None,
                sys::ksnp_client_event_type::KSNP_CLIENT_EVENT_HANDSHAKE => {
                    ClientEvent::from(value.anon_1.handshake)
                }
                sys::ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_OPEN => {
                    ClientEvent::from_stream_open(value.anon_1.stream_open)
                }
                sys::ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_CLOSE => {
                    ClientEvent::from_stream_close(value.anon_1.stream_close)
                }
                sys::ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_SUSPEND => {
                    ClientEvent::from(value.anon_1.stream_suspend)
                }
                sys::ksnp_client_event_type::KSNP_CLIENT_EVENT_STREAM_KEY_DATA => {
                    ClientEvent::from_key_data(value.anon_1.key_data)
                }
                sys::ksnp_client_event_type::KSNP_CLIENT_EVENT_KEEP_ALIVE => {
                    ClientEvent::from_keep_alive(value.anon_1.keep_alive)
                }
                sys::ksnp_client_event_type::KSNP_CLIENT_EVENT_ERROR => {
                    ClientEvent::from(value.anon_1.error)
                }
                // ASSERT: The type must be one of constants of the
                // client_event_type enumeration.
                _ => unreachable!(),
            }
        };
        Some(event)
    }
}
