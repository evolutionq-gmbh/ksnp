use core::{
    ffi::CStr,
    mem::MaybeUninit,
    num::NonZero,
    ptr::{self, NonNull, null, null_mut},
    time::Duration,
};

use uuid::Uuid;

use crate::{
    message::MessageContext,
    processor::Processor,
    sys::{self, ksnp_error},
    types::{StreamAcceptedParams, StreamOpenParams, StreamQosParams, map_err},
};

/// Wrapper for a [`sys::ksnp_server`].
pub struct ServerConnection {
    ctx: MessageContext,
    server: *mut sys::ksnp_server,
}

// SAFETY: The sys::ksnp_server_connection can be moved across threads safely.
unsafe impl Send for ServerConnection {}

impl Drop for ServerConnection {
    fn drop(&mut self) {
        // SAFETY: self.server is valid for the lifetime of this wrapper.
        unsafe { sys::ksnp_server_destroy(self.server) };
    }
}

impl<'ctx> ServerConnection {
    /// Creates a new [`sys::ksnp_server_connection`] wrapper with a new
    /// server_connection that uses the given [`MessageContext`].
    pub fn new(ctx: MessageContext) -> Option<Self> {
        let mut this = Self {
            ctx,
            server: null_mut(),
        };
        // SAFETY: server is a valid writeable pointer, and the message context
        // does not move its internal pointer.
        if unsafe { sys::ksnp_server_create(&raw mut this.server, this.ctx.ctx) }.0 != 0 {
            None
        } else {
            Some(this)
        }
    }

    /// Opens a new stream.
    pub fn open_stream_ok<T: StreamImpl>(
        &mut self,
        stream: &'ctx mut Stream<T>,
        params: &StreamAcceptedParams,
    ) -> Result<(), ksnp_error> {
        // SAFETY: The pointers in the stream parameters stay valid for the
        // lifetime of the params arguments.
        let sys_params = unsafe { params.to_sys() };
        // SAFETY: self.server is mutably accessible. The stream parameter has a
        // lifetime matching that of this server connection, so it will remain
        // valid long enough (with exclusive rights). Its stream pointer is
        // given directly to the server and not modified otherwise. The
        // parameters are a valid object on the stack.
        map_err(unsafe {
            sys::ksnp_server_open_stream_ok(
                self.server,
                stream.stream_ptr_mut(),
                &raw const sys_params,
            )
        })?;
        Ok(())
    }

    /// Opens a new stream.
    ///
    /// # Safety
    ///
    /// The provided stream pointer must remain valid until the server returns
    /// the pointer or is dropped.
    pub unsafe fn open_stream_ok_ptr<T: StreamImpl>(
        &mut self,
        stream: *mut Stream<T>,
        params: &StreamAcceptedParams,
    ) -> Result<(), ksnp_error> {
        // SAFETY: The pointers in the stream parameters stay valid for the
        // lifetime of the params arguments.
        let sys_params = unsafe { params.to_sys() };
        // SAFETY: self.server is mutably accessible. The stream parameter will
        // remain valid long enough. Its stream pointer is given directly to the
        // server and not modified otherwise. The parameters are a valid object
        // on the stack.
        map_err(unsafe {
            sys::ksnp_server_open_stream_ok(
                self.server,
                stream.as_mut().unwrap().stream_ptr_mut(),
                &raw const sys_params,
            )
        })?;
        Ok(())
    }

    pub fn open_stream_fail(
        &mut self,
        reason: u32,
        params: Option<&StreamQosParams>,
        message: Option<&CStr>,
    ) -> Result<(), ksnp_error> {
        let params = params.map(|p| {
            // SAFETY: The pointers in the stream parameters stay valid for the
            // lifetime of the params arguments.
            unsafe { p.to_sys() }
        });
        // SAFETY: self.server is mutably accessible. Other pointers are valid
        // for the duration of this function.
        map_err(unsafe {
            sys::ksnp_server_open_stream_fail(
                self.server,
                ksnp_sys::ksnp_status_code(reason),
                params.as_ref().map_or(null(), ptr::from_ref),
                message.map_or(null(), CStr::as_ptr),
            )
        })?;
        Ok(())
    }

    pub fn suspend_stream_ok(&mut self, timeout: u32) -> Result<(), ksnp_error> {
        let mut stream = null_mut();
        // SAFETY: self.server is mutably accessible. The stream pointer is a
        // valid stack value.
        map_err(unsafe {
            sys::ksnp_server_suspend_stream_ok(self.server, timeout, &raw mut stream)
        })?;
        Ok(())
    }

    pub fn suspend_stream_fail(
        &mut self,
        reason: u32,
        message: Option<&CStr>,
    ) -> Result<(), ksnp_error> {
        // SAFETY: self.server is mutably accessible. Other pointers are valid
        // for the duration of this function.
        map_err(unsafe {
            sys::ksnp_server_suspend_stream_fail(
                self.server,
                ksnp_sys::ksnp_status_code(reason),
                message.map_or(null(), CStr::as_ptr),
            )
        })?;
        Ok(())
    }

    pub fn close_stream(&mut self) -> Result<*mut sys::ksnp_stream, ksnp_error> {
        let mut stream = null_mut();
        // SAFETY: self.server is mutably accessible. The stream pointer is a
        // valid stack value.
        map_err(unsafe { sys::ksnp_server_close_stream(self.server, &raw mut stream) })?;
        Ok(stream)
    }

    pub fn server_keep_alive_ok(&mut self) -> Result<(), ksnp_error> {
        // SAFETY: self.server is mutably accessible.
        map_err(unsafe { sys::ksnp_server_keep_alive_ok(self.server) })?;
        Ok(())
    }

    pub fn server_keep_alive_fail(
        &mut self,
        reason: u32,
        message: Option<&CStr>,
    ) -> Result<(), ksnp_error> {
        // SAFETY: self.server is mutably accessible. Other pointers are valid
        // for the duration of this function.
        map_err(unsafe {
            sys::ksnp_server_keep_alive_fail(
                self.server,
                ksnp_sys::ksnp_status_code(reason),
                message.map_or(null(), CStr::as_ptr),
            )
        })?;
        Ok(())
    }
}

pub trait StreamImpl {
    /// Returns the chunk size for this stream.
    ///
    /// The value does not change over the lifetime of the stream.
    fn chunk_size(&self) -> u16;

    /// Checks if at least one chunk's worth of key data is available.
    fn has_chunk_available(&self) -> bool;

    /// Returns the next available chunk of key data, or a multiple thereof.
    ///
    /// The max_count parameter determines how many chunks of key data may be
    /// returned. If [`None`], all chunks available may be returned.
    fn next_chunk(&mut self, max_count: Option<NonZero<u16>>) -> Result<&[u8], ksnp_error>;
}

// It is important the base member is the first member.
#[repr(C)]
pub struct Stream<T> {
    // Note that no method may modify base after being constructed, so it can
    // safely be shared with a server.
    base: sys::ksnp_stream,
    this: T,
}

impl<T: StreamImpl> Stream<T> {
    const BASE_OFFSET: usize = core::mem::offset_of!(Self, base);

    /// Converts a raw stream pointer to a self reference.
    ///
    /// # Safety
    ///
    /// The pointer must have been created from the address of Self::base, and
    /// point into a valid instance of self. Furthermore, the lifetime of the
    /// resulting reference may not exceed that of the given pointer.
    unsafe fn stream_to_self<'a>(stream: *const sys::ksnp_stream) -> &'a Self {
        // SAFETY: The stream parameter points to an instance of Self::base,
        // so the self pointer is found by subtracting the base offset.
        unsafe { stream.byte_sub(Self::BASE_OFFSET).cast::<Self>().as_ref() }.unwrap()
    }

    /// Converts a raw stream pointer to a mutable self reference.
    ///
    /// # Safety
    ///
    /// The pointer must have been created from the address of Self::base, and
    /// point into a valid instance of self. Furthermore, the lifetime of the
    /// resulting reference may not exceed that of the given pointer.
    unsafe fn stream_to_self_mut<'a>(stream: *mut sys::ksnp_stream) -> &'a mut Self {
        // SAFETY: The stream parameter points to an instance of Self::base,
        // so the self pointer is found by subtracting the base offset.
        unsafe { stream.byte_sub(Self::BASE_OFFSET).cast::<Self>().as_mut() }.unwrap()
    }

    pub fn new(this: T) -> Self {
        Self {
            base: sys::ksnp_stream {
                chunk_size: this.chunk_size(),
                has_chunk_available: Some(Self::has_chunk_available),
                next_chunk: Some(Self::next_chunk),
            },
            this,
        }
    }

    /// Returns a pointer to the sys::ksnp_stream object within.
    ///
    /// This pointer can be used to have a server use this stream.
    ///
    /// # Safety
    ///
    /// The resulting pointer may not be modified as long as it is in use by a
    /// server, or a mutable reference is held to this stream.
    pub(crate) unsafe fn stream_ptr_mut(&mut self) -> *mut sys::ksnp_stream {
        &raw mut self.base
    }

    extern "C" fn has_chunk_available(stream: *const sys::ksnp_stream) -> bool {
        // SAFETY: The stream parameter points to an instance of Self::base,
        // as only the base's has_chunk_available method can call here.
        unsafe { Self::stream_to_self(stream) }
            .this
            .has_chunk_available()
    }

    extern "C" fn next_chunk(
        stream: *mut sys::ksnp_stream,
        data: *mut sys::ksnp_data,
        max_count: u16,
    ) -> ksnp_error {
        // SAFETY: The stream parameter points to an instance of Self::base,
        // as only the base's next_chunk method can call here.
        let chunk = match unsafe { Self::stream_to_self_mut(stream) }
            .this
            .next_chunk(NonZero::new(max_count))
        {
            Ok(chunk) => chunk,
            Err(e) => return e,
        };

        // SAFETY: The data pointer points to a valid writeable object. The
        // resulting chunk slice will have a lifetime matching this function
        // body. However,
        let data = unsafe { data.as_mut() }.unwrap();
        data.data = chunk.as_ptr();
        data.len = chunk.len();
        ksnp_error(0)
    }

    pub fn stream_impl(&self) -> &T {
        &self.this
    }

    pub fn stream_impl_mut(&mut self) -> &mut T {
        &mut self.this
    }
}

impl<T: StreamImpl> From<T> for Stream<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl Processor for ServerConnection {
    type Value<'a>
        = Option<ServerEvent<'a>>
    where
        Self: 'a;

    fn want_read(&self) -> bool {
        // SAFETY: self.server is valid for the lifetime of this wrapper.
        unsafe { sys::ksnp_server_want_read(self.server) }
    }

    fn want_write(&self) -> bool {
        // SAFETY: self.server is valid for the lifetime of this wrapper.
        unsafe { sys::ksnp_server_want_write(self.server) }
    }

    fn read_data(&mut self, data: &[u8]) -> Result<usize, ksnp_error> {
        let mut len = data.len();
        // SAFETY: self.server is valid for the lifetime of this wrapper, the
        // buffer and size pointers are derived from valid instances, len is
        // initialized properly.
        map_err(unsafe { sys::ksnp_server_read_data(self.server, data.as_ptr(), &raw mut len) })?;
        Ok(len)
    }

    fn write_data(&mut self, data: &mut [MaybeUninit<u8>]) -> Result<usize, ksnp_error> {
        let mut len = data.len();
        // SAFETY: self.server is valid for the lifetime of this wrapper, the
        // buffer and size pointers are derived from valid instances, len is
        // initialized properly.
        map_err(unsafe {
            sys::ksnp_server_write_data(self.server, data.as_mut_ptr().cast::<u8>(), &raw mut len)
        })?;
        Ok(len)
    }

    fn next_event(&mut self) -> Result<Self::Value<'_>, ksnp_error> {
        let mut event = MaybeUninit::uninit();
        // SAFETY: self.server is valid for the lifetime of this wrapper, the
        // event pointer is writeable.
        map_err(unsafe { sys::ksnp_server_next_event(self.server, event.as_mut_ptr()) })?;
        // SAFETY: On success the event is valid and assume_init can be called.
        // The event is valid for the current exclusive borrow of self, as it
        // prevents any other the other server methods from being called.
        Ok(unsafe { ServerEvent::from_event(event.assume_init()) })
    }
}

pub enum ServerEvent<'ctx> {
    Handshake {
        protocol: u8,
    },
    OpenStream {
        parameters: StreamOpenParams<'ctx>,
    },
    CloseStream {
        stream: NonNull<sys::ksnp_stream>,
    },
    SuspendStream {
        timeout: Duration,
    },
    KeepAlive {
        stream_id: Uuid,
    },
    NewCapacity {
        additional_capacity: u32,
        current_capacity: u32,
    },
    Error {
        code: u32,
        stream: Option<NonNull<sys::ksnp_stream>>,
    },
}

impl ServerEvent<'_> {
    /// Converts a server event from a raw open stream event.
    ///
    /// # Safety
    ///
    /// The event must point to data that is valid for the lifetime of this
    /// server event.
    unsafe fn from_open_stream(value: sys::ksnp_server_event_open_stream) -> Self {
        Self::OpenStream {
            parameters: StreamOpenParams::from_open_params(
                // ASSERT: An open stream event must have a valid parameters
                // object.
                // SAFETY: An open stream event points to a valid parameters
                // object.
                unsafe { value.parameters.as_ref() }.unwrap(),
            ),
        }
    }
}

impl From<sys::ksnp_server_event_handshake> for ServerEvent<'_> {
    fn from(value: sys::ksnp_server_event_handshake) -> Self {
        Self::Handshake {
            protocol: value.protocol.0,
        }
    }
}

impl From<sys::ksnp_server_event_close_stream> for ServerEvent<'_> {
    fn from(value: sys::ksnp_server_event_close_stream) -> Self {
        Self::CloseStream {
            stream: NonNull::new(value.stream).unwrap(),
        }
    }
}

impl From<sys::ksnp_server_event_suspend_stream> for ServerEvent<'_> {
    fn from(value: sys::ksnp_server_event_suspend_stream) -> Self {
        Self::SuspendStream {
            timeout: Duration::from_secs(value.timeout.into()),
        }
    }
}

impl From<sys::ksnp_server_event_keep_alive> for ServerEvent<'_> {
    fn from(value: sys::ksnp_server_event_keep_alive) -> Self {
        Self::KeepAlive {
            stream_id: Uuid::from_bytes(value.stream_id),
        }
    }
}

impl From<sys::ksnp_server_event_new_capacity> for ServerEvent<'_> {
    fn from(value: sys::ksnp_server_event_new_capacity) -> Self {
        Self::NewCapacity {
            additional_capacity: value.additional_capacity,
            current_capacity: value.current_capacity,
        }
    }
}

impl From<sys::ksnp_server_event_error> for ServerEvent<'_> {
    fn from(value: sys::ksnp_server_event_error) -> Self {
        Self::Error {
            code: value.code.0,
            stream: NonNull::new(value.stream),
        }
    }
}

impl ServerEvent<'_> {
    /// Converts a server event from a raw event.
    ///
    /// # Safety
    ///
    /// The event must point to data that is valid for the lifetime of this
    /// server event.
    pub unsafe fn from_event(value: sys::ksnp_server_event) -> Option<Self> {
        // SAFETY: The union's type dictates which field is set.
        let event = unsafe {
            match value.type_ {
                sys::ksnp_server_event_type::KSNP_SERVER_EVENT_NONE => return None,
                sys::ksnp_server_event_type::KSNP_SERVER_EVENT_HANDSHAKE => {
                    ServerEvent::from(value.anon_1.handshake)
                }
                sys::ksnp_server_event_type::KSNP_SERVER_EVENT_OPEN_STREAM => {
                    ServerEvent::from_open_stream(value.anon_1.open_stream)
                }
                sys::ksnp_server_event_type::KSNP_SERVER_EVENT_CLOSE_STREAM => {
                    ServerEvent::from(value.anon_1.close_stream)
                }
                sys::ksnp_server_event_type::KSNP_SERVER_EVENT_SUSPEND_STREAM => {
                    ServerEvent::from(value.anon_1.suspend_stream)
                }
                sys::ksnp_server_event_type::KSNP_SERVER_EVENT_NEW_CAPACITY => {
                    ServerEvent::from(value.anon_1.new_capacity)
                }
                sys::ksnp_server_event_type::KSNP_SERVER_EVENT_KEEP_ALIVE => {
                    ServerEvent::from(value.anon_1.keep_alive)
                }
                sys::ksnp_server_event_type::KSNP_SERVER_EVENT_ERROR => {
                    ServerEvent::from(value.anon_1.error)
                }
                // ASSERT: The type must be one of constants of the
                // server_event_type enumeration.
                _ => unreachable!(),
            }
        };
        Some(event)
    }
}
