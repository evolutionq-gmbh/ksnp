use core::{
    any::Any,
    ffi::{CStr, c_uchar},
    fmt,
    mem::MaybeUninit,
    num::NonZero,
    pin::Pin,
    ptr::{self, null, null_mut},
    slice,
    time::Duration,
};

use uuid::Uuid;

use crate::{
    error::{Error, FailedReason, ProtocolError, StatusCode, check_err},
    sys::{self, ksnp_error},
    types::{StreamAcceptedParams, StreamOpenParams, StreamQosParams, string_ref},
};

pub trait BufferImpl: Any + Unpin {
    /// Return the data stored currently in the buffer
    fn data(&mut self) -> &mut [u8];

    /// Returns the size of the buffer.
    fn size(&self) -> usize;

    fn consume(&mut self, count: usize);

    fn append(&mut self, data: &[u8]) -> Result<usize, Error>;

    fn truncate(&mut self, count: usize);
}

// It is important the base member is the first member.
#[repr(C)]
pub struct Buffer<T: ?Sized> {
    // Note that no method may modify base after being constructed, so it can
    // safely be shared with a server.
    base: sys::ksnp_buffer,
    this: T,
}

impl<T: ?Sized> fmt::Debug for Buffer<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl<T: BufferImpl> Buffer<T> {
    const BASE_OFFSET: usize = core::mem::offset_of!(Self, base);

    /// Converts a raw stream pointer to a mutable self reference.
    ///
    /// # Safety
    ///
    /// The pointer must have been created from the address of Self::base, and
    /// point into a valid instance of self. Furthermore, the lifetime of the
    /// resulting reference may not exceed that of the given pointer.
    unsafe fn buffer_to_self_mut<'a>(buffer: *mut sys::ksnp_buffer) -> &'a mut Self {
        // SAFETY: The stream parameter points to an instance of Self::base,
        // so the self pointer is found by subtracting the base offset.
        unsafe { buffer.byte_sub(Self::BASE_OFFSET).cast::<Self>().as_mut() }.unwrap()
    }

    pub fn new(this: T) -> Self {
        Self {
            base: sys::ksnp_buffer {
                contents: Some(Self::contents),
                consume: Some(Self::consume),
                append: Some(Self::append),
                truncate: Some(Self::truncate),
                user_data: null_mut(),
            },
            this,
        }
    }

    extern "C" fn contents(buffer: *mut sys::ksnp_buffer, data: *mut sys::ksnp_data) {
        // SAFETY: The buffer parameter points to an instance of Self::base, as
        // only the base's data method can call here.
        let contents = unsafe { Self::buffer_to_self_mut(buffer) }.this.data();
        let contents = sys::ksnp_data {
            data: contents.as_mut_ptr(),
            len: contents.len(),
        };
        // SAFETY: The function requires the data argument to be a valid
        // writeable pointer.
        unsafe { data.write(contents) };
    }

    extern "C" fn consume(buffer: *mut sys::ksnp_buffer, count: usize) {
        // SAFETY: The buffer parameter points to an instance of Self::base, as
        // only the base's size method can call here.
        unsafe { Self::buffer_to_self_mut(buffer) }
            .this
            .consume(count);
    }

    extern "C" fn append(
        buffer: *mut sys::ksnp_buffer,
        data: *const c_uchar,
        len: *mut usize,
    ) -> ksnp_error {
        // SAFETY: The buffer parameter points to an instance of Self::base, as
        // only the base's size method can call here.
        match unsafe { Self::buffer_to_self_mut(buffer) }
            .this
            // SAFETY: The input buffer points to valid data and len is a valid
            // readable pointer.
            .append(unsafe { slice::from_raw_parts(data, len.read()) })
        {
            Ok(count) => {
                // SAFETY: len is a valid writeable pointer.
                unsafe { len.write(count) };
                ksnp_error::KSNP_E_NO_ERROR
            }
            Err(e) => e.into(),
        }
    }

    extern "C" fn truncate(buffer: *mut sys::ksnp_buffer, count: usize) {
        // SAFETY: The buffer parameter points to an instance of Self::base, as
        // only the base's size method can call here.
        unsafe { Self::buffer_to_self_mut(buffer) }
            .this
            .truncate(count);
    }
}

impl<T: ?Sized> Buffer<T> {
    /// Returns a pointer to the sys::ksnp_buffer object within.
    ///
    /// This pointer can be used to have a message context use this buffer.
    ///
    /// # Safety
    ///
    /// The resulting pointee may not be modified via this pointer. However,
    /// the callbacks defined within may be used to perform modifications.
    pub(crate) unsafe fn buffer_ptr(&self) -> *mut sys::ksnp_buffer {
        (&raw const self.base).cast_mut()
    }

    pub fn buffer_impl(&self) -> &T {
        &self.this
    }

    pub fn buffer_impl_mut(&mut self) -> &mut T {
        &mut self.this
    }
}

impl<T: BufferImpl> From<T> for Buffer<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl BufferImpl for Vec<u8> {
    fn data(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }

    fn size(&self) -> usize {
        self.len()
    }

    fn consume(&mut self, count: usize) {
        self.drain(..count);
    }

    fn append(&mut self, data: &[u8]) -> Result<usize, Error> {
        if self.try_reserve(data.len()).is_err() {
            // ASSERT: ksnp_error::KSNP_E_NO_MEM is a concrete error
            return Err(Error::from_error(ksnp_error::KSNP_E_NO_MEM));
        }
        self.extend_from_slice(data);
        Ok(data.len())
    }

    fn truncate(&mut self, count: usize) {
        self.truncate(count);
    }
}

type BufferPtr = Box<Buffer<dyn BufferImpl>>;

/// Wrapper for a [`sys::ksnp_message_context`].
pub struct MessageContext {
    pub(crate) ctx: *mut sys::ksnp_message_context,
    buffers: Option<(Pin<BufferPtr>, Pin<BufferPtr>)>,
}

// SAFETY: The sys::ksnp_message_context can be moved across threads safely.
unsafe impl Send for MessageContext {}

impl Drop for MessageContext {
    fn drop(&mut self) {
        // SAFETY: self.ctx is valid for the lifetime of this wrapper.
        unsafe { sys::ksnp_message_context_destroy(self.ctx) };
    }
}

impl MessageContext {
    /// Creates a new [`sys::ksnp_message_context`] wrapper with a new
    /// message_context.
    ///
    /// The default read and write buffers are used for the message context.
    /// Therefore, data must be read and written using [`Self::read_data`] and
    /// [`Self::write_data`].
    pub fn new() -> Result<Self, Error> {
        let mut ctx: *mut sys::ksnp_message_context = null_mut();
        // SAFETY: ctx is a valid writeable pointer.
        check_err(unsafe { sys::ksnp_message_context_create(&raw mut ctx) })?;
        Ok(Self { ctx, buffers: None })
    }

    /// Creates a new [`sys::ksnp_message_context`] wrapper with a new
    /// message_context that uses user-provided buffers.
    ///
    /// Data can be read/written using either [`Self::read_data`] and
    /// [`Self::write_data`], or by interacting with the buffers directly, which
    /// are accessible via [`Self::read_buf`] and [`Self::write_buf`].
    pub fn with_buffers<T: BufferImpl + 'static, U: BufferImpl + 'static>(
        read_buffer: T,
        write_buffer: U,
    ) -> Result<Self, Error> {
        let read_buffer = Box::pin(Buffer::new(read_buffer));
        let write_buffer = Box::pin(Buffer::new(write_buffer));

        let mut ctx: *mut sys::ksnp_message_context = null_mut();
        // SAFETY: ctx is a valid writeable pointer. The buffer pointers will
        // not move since they are contained by Arc.
        check_err(unsafe {
            sys::ksnp_message_context_create_with_buffer(
                &raw mut ctx,
                read_buffer.buffer_ptr(),
                write_buffer.buffer_ptr(),
            )
        })?;
        Ok(Self {
            ctx,
            buffers: Some((read_buffer, write_buffer)),
        })
    }

    /// Gets a reference to the read buffer that was used when this context was
    /// constructed.
    ///
    /// The resulting reference can be downcast to a concrete type using the
    /// [`Any`] trait.
    ///
    /// If no buffers were specified, returns None.
    pub fn read_buf(&self) -> Option<&dyn BufferImpl> {
        self.buffers
            .as_ref()
            .map(|(read_buffer, _)| Buffer::buffer_impl(read_buffer))
    }

    /// Gets a mutable reference to the read buffer that was used when this
    /// context was constructed.
    ///
    /// The resulting reference can be downcast to a concrete type using the
    /// [`Any`] trait.
    ///
    /// If no buffers were specified, returns None.
    pub fn read_buf_mut(&mut self) -> Option<&mut dyn BufferImpl> {
        self.buffers
            .as_mut()
            .map(|(read_buffer, _)| Buffer::buffer_impl_mut(read_buffer))
    }

    /// Gets a reference to the write buffer that was used when this context was
    /// constructed.
    ///
    /// The resulting reference can be downcast to a concrete type using the
    /// [`Any`] trait.
    ///
    /// If no buffers were specified, returns None.
    pub fn write_buf(&self) -> Option<&dyn BufferImpl> {
        self.buffers
            .as_ref()
            .map(|(_, write_buffer)| Buffer::buffer_impl(write_buffer))
    }

    /// Gets a mutable reference to the write buffer that was used when this
    /// context was constructed.
    ///
    /// The resulting reference can be downcast to a concrete type using the
    /// [`Any`] trait.
    ///
    /// If no buffers were specified, returns None.
    pub fn write_buf_mut(&mut self) -> Option<&mut dyn BufferImpl> {
        self.buffers
            .as_mut()
            .map(|(_, write_buffer)| Buffer::buffer_impl_mut(write_buffer))
    }

    /// Gets a mutable reference to the read and write buffers that were used
    /// when this context was constructed.
    ///
    /// The resulting references can be downcast to concrete types using the
    /// [`Any`] trait.
    ///
    /// If no buffers were specified, returns None.
    pub fn buffers_mut(&mut self) -> Option<(&mut dyn BufferImpl, &mut dyn BufferImpl)> {
        self.buffers.as_mut().map(|(read_buffer, write_buffer)| {
            (
                Buffer::buffer_impl_mut(read_buffer),
                Buffer::buffer_impl_mut(write_buffer),
            )
        })
    }

    /// Writes the given message into the write buffer used by the context.
    pub fn write_message(&mut self, message: Message<'_>) -> Result<(), Error> {
        let mut scratch = None;
        // SAFETY: The pointers inside the message are valid for the duration of
        // this call, as the argument stays valid. The scratch space is not
        // modified by this function.
        let message = unsafe { message.try_to_sys(&mut scratch) }?;
        // SAFETY: The message and scratch space are valid for the duration of
        // this call and not modified.
        check_err(unsafe {
            sys::ksnp_message_context_write_message(self.ctx, &raw const message)
        })?;
        Ok(())
    }

    /// Checks if more data is expected from the read buffer.
    pub fn want_read(&self) -> bool {
        // SAFETY: self.ctx is valid for the lifetime of this wrapper.
        unsafe { sys::ksnp_message_context_want_read(self.ctx) }
    }

    /// Checks if more data can be written using the write buffer.
    pub fn want_write(&self) -> bool {
        // SAFETY: self.ctx is valid for the lifetime of this wrapper.
        unsafe { sys::ksnp_message_context_want_write(self.ctx) }
    }

    /// Reads the given data into the read buffer.
    ///
    /// Returns the number of bytes read.
    pub fn read_data(&mut self, data: &[u8]) -> Result<usize, Error> {
        let mut len = data.len();
        // SAFETY: self.ctx is valid for the lifetime of this wrapper, the
        // buffer and size pointers are derived from valid instances, len is
        // initialized properly.
        check_err(unsafe {
            sys::ksnp_message_context_read_data(self.ctx, data.as_ptr(), &raw mut len)
        })?;
        Ok(len)
    }

    /// Writes the stored data into the given buffer.
    ///
    /// Returns the number of bytes written.
    pub fn write_data(&mut self, data: &mut [MaybeUninit<u8>]) -> Result<usize, Error> {
        let mut len = data.len();
        // SAFETY: self.ctx is valid for the lifetime of this wrapper, the
        // buffer and size pointers are derived from valid instances, len is
        // initialized properly.
        check_err(unsafe {
            sys::ksnp_message_context_write_data(
                self.ctx,
                data.as_mut_ptr().cast::<u8>(),
                &raw mut len,
            )
        })?;
        Ok(len)
    }

    /// Returns the next message event, if any.
    pub fn next_event(&mut self) -> Result<MessageResult<'_>, Error> {
        let mut message = MaybeUninit::uninit();
        let mut protocol_error = sys::ksnp_protocol_error {
            code: sys::ksnp_error_code::KSNP_PROT_E_UNKNOWN_ERROR,
            description: null(),
        };
        // SAFETY: self.ctx is valid for the lifetime of this wrapper, the value
        // pointer is writeable.
        match unsafe {
            sys::ksnp_message_context_next_message(
                self.ctx,
                message.as_mut_ptr(),
                &raw mut protocol_error,
            )
        } {
            ksnp_error::KSNP_E_NO_ERROR => {
                // SAFETY: On success the message is valid and assume_init can
                // be called. The message data is valid for the current
                // exclusive borrow of self, as it prevents any other context
                // methods from being called.
                let msg =
                    MessageResult::from(unsafe { Message::from_message(message.assume_init()) });
                Ok(msg)
            }
            ksnp_error::KSNP_E_PROTOCOL_ERROR => {
                Ok(MessageResult::ProtocolError {
                    code: protocol_error.code.into(),
                    // SAFETY: The description is valid as long as this context is
                    // not modified, which it can't due to the exclusive reference.
                    description: unsafe { string_ref(protocol_error.description) },
                })
            }
            // ASSERT: ksnp_error::KSNP_E_NO_ERROR is handled in the above
            // branch
            e => Err(Error::from_error(e)),
        }
    }
}

#[derive(Debug)]
pub enum Message<'ctx> {
    Error {
        code: ProtocolError,
    },
    Version {
        minimum_version: u8,
        maximum_version: u8,
    },
    OpenStream {
        parameters: StreamOpenParams<'ctx>,
    },
    OpenStreamReply {
        parameters: StreamAcceptedParams<'ctx>,
    },
    OpenStreamFailed {
        code: FailedReason,
        parameters: Option<StreamQosParams<'ctx>>,
        message: Option<&'ctx CStr>,
    },
    CloseStream,
    CloseStreamReply,
    CloseStreamNotify {
        code: sys::ksnp_status_code,
        message: Option<&'ctx CStr>,
    },
    SuspendStream {
        timeout: Duration,
    },
    SuspendStreamReply {
        timeout: Duration,
    },
    SuspendStreamFailed {
        code: FailedReason,
        message: Option<&'ctx CStr>,
    },
    SuspendStreamNotify {
        code: StatusCode,
        timeout: Duration,
    },
    KeepAlive {
        stream_id: Uuid,
    },
    KeepAliveReply,
    KeepAliveFailed {
        code: FailedReason,
        message: Option<&'ctx CStr>,
    },
    CapacityNotify {
        additional_capacity: u32,
    },
    KeyDataNotify {
        key_data: &'ctx [u8],
    },
}

#[derive(Debug)]
pub enum MessageResult<'ctx> {
    None,
    Message(Message<'ctx>),
    ProtocolError {
        code: ProtocolError,
        description: Option<&'ctx CStr>,
    },
}

impl<'ctx> From<Option<Message<'ctx>>> for MessageResult<'ctx> {
    fn from(value: Option<Message<'ctx>>) -> Self {
        match value {
            Some(m) => Self::Message(m),
            None => Self::None,
        }
    }
}

pub(crate) enum StreamParams {
    Open(sys::ksnp_stream_open_params),
    Accepted(sys::ksnp_stream_accepted_params),
    Qos(sys::ksnp_stream_qos_params),
}

impl Message<'_> {
    /// Creates a sys::ksnp_message from this message.
    ///
    /// The scratch object is used to store a temporary parameters object. The
    /// result of this method is only valid for as long as the scratch object
    /// is not modified.
    ///
    /// # Safety
    ///
    /// The resulting structure points to data referenced by this message.
    /// Although creating a pointer is always safe, using it is only possible as
    /// long as this message and the scratch space are not modified in any way.
    pub(crate) unsafe fn try_to_sys(
        &self,
        scratch: &mut Option<StreamParams>,
    ) -> Result<sys::ksnp_message, Error> {
        let msg = match self {
            &Self::Error { code } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_ERROR,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    error: sys::ksnp_msg_error { code: code.into() },
                },
            },
            &Self::Version {
                minimum_version,
                maximum_version,
            } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_VERSION,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    version: sys::ksnp_msg_version {
                        minimum_version: sys::ksnp_protocol_version(minimum_version),
                        maximum_version: sys::ksnp_protocol_version(maximum_version),
                    },
                },
            },
            Self::OpenStream { parameters } => {
                // SAFETY: The pointers of the resulting parameters object can
                // only be used as specified by this method's documentation.
                *scratch = Some(StreamParams::Open(unsafe { parameters.to_sys() }));
                let Some(StreamParams::Open(parameters)) = &scratch else {
                    unreachable!()
                };
                sys::ksnp_message {
                    type_: sys::ksnp_message_type::KSNP_MSG_OPEN_STREAM,
                    anon_1: sys::ksnp_message__bindgen_ty_1 {
                        open_stream: sys::ksnp_msg_open_stream {
                            parameters: ptr::from_ref(parameters),
                        },
                    },
                }
            }
            Self::OpenStreamReply { parameters } => {
                // SAFETY: The pointers of the resulting parameters
                // object can only be used as specified by this method's
                // documentation.
                *scratch = Some(StreamParams::Accepted(unsafe { parameters.to_sys() }));
                let Some(StreamParams::Accepted(parameters)) = &scratch else {
                    unreachable!()
                };
                let parameters = sys::ksnp_stream_reply_params {
                    reply: ptr::from_ref(parameters),
                };

                sys::ksnp_message {
                    type_: sys::ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY,
                    anon_1: sys::ksnp_message__bindgen_ty_1 {
                        open_stream_reply: sys::ksnp_msg_open_stream_reply {
                            code: sys::ksnp_status_code::KSNP_STATUS_SUCCESS,
                            message: null(),
                            parameters,
                        },
                    },
                }
            }
            Self::OpenStreamFailed {
                code,
                parameters,
                message,
            } => {
                let parameters = match parameters {
                    Some(params) => {
                        // SAFETY: The pointers of the resulting parameters
                        // object can only be used as specified by this method's
                        // documentation.
                        *scratch = Some(StreamParams::Qos(unsafe { params.to_sys() }));
                        let Some(StreamParams::Qos(parameters)) = &scratch else {
                            unreachable!()
                        };
                        sys::ksnp_stream_reply_params {
                            qos: ptr::from_ref(parameters),
                        }
                    }
                    None => sys::ksnp_stream_reply_params { qos: null() },
                };

                sys::ksnp_message {
                    type_: sys::ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY,
                    anon_1: sys::ksnp_message__bindgen_ty_1 {
                        open_stream_reply: sys::ksnp_msg_open_stream_reply {
                            code: (*code).into(),
                            message: message.map_or(null(), CStr::as_ptr),
                            parameters,
                        },
                    },
                }
            }
            Self::CloseStream => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_CLOSE_STREAM,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    close_stream: sys::ksnp_msg_close_stream { unused: [0] },
                },
            },
            Self::CloseStreamReply => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_CLOSE_STREAM_REPLY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    close_stream_reply: sys::ksnp_msg_close_stream_reply { unused: [0] },
                },
            },
            &Self::CloseStreamNotify { code, message } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_CLOSE_STREAM_NOTIFY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    close_stream_notify: sys::ksnp_msg_close_stream_notify {
                        code,
                        message: message.map_or(null(), CStr::as_ptr),
                    },
                },
            },
            &Self::SuspendStream { timeout } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    suspend_stream: sys::ksnp_msg_suspend_stream {
                        timeout: timeout.as_secs().try_into().map_err(|_| {
                            // ASSERT: ksnp_error::KSNP_E_INVALID_ARGUMENT is a
                            // concrete error.
                            Error::try_from(ksnp_error::KSNP_E_INVALID_ARGUMENT).unwrap()
                        })?,
                    },
                },
            },
            &Self::SuspendStreamReply { timeout } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    suspend_stream_reply: sys::ksnp_msg_suspend_stream_reply {
                        code: sys::ksnp_status_code::KSNP_STATUS_SUCCESS,
                        timeout: timeout.as_secs().try_into().map_err(|_| {
                            // ASSERT: ksnp_error::KSNP_E_INVALID_ARGUMENT is a
                            // concrete error.
                            Error::try_from(ksnp_error::KSNP_E_INVALID_ARGUMENT).unwrap()
                        })?,
                        message: null(),
                    },
                },
            },
            &Self::SuspendStreamFailed { code, message } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    suspend_stream_reply: sys::ksnp_msg_suspend_stream_reply {
                        code: code.into(),
                        timeout: 0,
                        message: message.map_or(null(), CStr::as_ptr),
                    },
                },
            },
            &Self::SuspendStreamNotify { code, timeout } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    suspend_stream_notify: sys::ksnp_msg_suspend_stream_notify {
                        code: code.into(),
                        timeout: timeout.as_secs().try_into().map_err(|_| {
                            // ASSERT: ksnp_error::KSNP_E_INVALID_ARGUMENT is a
                            // concrete error.
                            Error::try_from(ksnp_error::KSNP_E_INVALID_ARGUMENT).unwrap()
                        })?,
                    },
                },
            },
            &Self::KeepAlive { stream_id } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    keep_alive_stream: sys::ksnp_msg_keep_alive_stream {
                        key_stream_id: stream_id.into_bytes(),
                    },
                },
            },
            &Self::KeepAliveReply => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    keep_alive_stream_reply: sys::ksnp_msg_keep_alive_stream_reply {
                        code: sys::ksnp_status_code::KSNP_STATUS_SUCCESS,
                        message: null(),
                    },
                },
            },
            &Self::KeepAliveFailed { code, message } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    keep_alive_stream_reply: sys::ksnp_msg_keep_alive_stream_reply {
                        code: code.into(),
                        message: message.map_or(null(), CStr::as_ptr),
                    },
                },
            },
            &Self::CapacityNotify {
                additional_capacity,
            } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_CAPACITY_NOTIFY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    capacity_notify: sys::ksnp_msg_capacity_notify {
                        additional_capacity,
                    },
                },
            },
            &Self::KeyDataNotify { key_data } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_KEY_DATA_NOTIFY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    key_data_notify: sys::ksnp_msg_key_data_notify {
                        key_data: sys::ksnp_cdata {
                            data: key_data.as_ptr(),
                            len: key_data.len(),
                        },
                        parameters: null_mut(),
                    },
                },
            },
        };
        Ok(msg)
    }
}

impl From<sys::ksnp_msg_error> for Message<'_> {
    fn from(value: sys::ksnp_msg_error) -> Self {
        Self::Error {
            code: value.code.into(),
        }
    }
}

impl From<sys::ksnp_msg_version> for Message<'_> {
    fn from(value: sys::ksnp_msg_version) -> Self {
        Self::Version {
            minimum_version: value.minimum_version.0,
            maximum_version: value.maximum_version.0,
        }
    }
}

impl From<sys::ksnp_msg_close_stream> for Message<'_> {
    fn from(_value: sys::ksnp_msg_close_stream) -> Self {
        Self::CloseStream
    }
}

impl From<sys::ksnp_msg_close_stream_reply> for Message<'_> {
    fn from(_value: sys::ksnp_msg_close_stream_reply) -> Self {
        Self::CloseStreamReply
    }
}

impl From<sys::ksnp_msg_suspend_stream> for Message<'_> {
    fn from(value: sys::ksnp_msg_suspend_stream) -> Self {
        Self::SuspendStream {
            timeout: Duration::from_secs(value.timeout.into()),
        }
    }
}

impl From<sys::ksnp_msg_suspend_stream_notify> for Message<'_> {
    fn from(value: sys::ksnp_msg_suspend_stream_notify) -> Self {
        Self::SuspendStreamNotify {
            code: value.code.into(),
            timeout: Duration::from_secs(value.timeout.into()),
        }
    }
}

impl From<sys::ksnp_msg_keep_alive_stream> for Message<'_> {
    fn from(value: sys::ksnp_msg_keep_alive_stream) -> Self {
        Self::KeepAlive {
            stream_id: Uuid::from_bytes(value.key_stream_id),
        }
    }
}

impl From<sys::ksnp_msg_capacity_notify> for Message<'_> {
    fn from(value: sys::ksnp_msg_capacity_notify) -> Self {
        Self::CapacityNotify {
            additional_capacity: value.additional_capacity,
        }
    }
}

impl Message<'_> {
    /// Converts a message from a raw open stream message.
    ///
    /// # Safety
    ///
    /// The raw message must point to data that is valid for the lifetime of
    /// this message.
    unsafe fn from_open_stream(value: sys::ksnp_msg_open_stream) -> Self {
        Self::OpenStream {
            // SAFETY: The input message must point to a valid parameters
            // object.
            parameters: StreamOpenParams::from_open_params(unsafe {
                value.parameters.as_ref().unwrap()
            }),
        }
    }

    /// Converts a message from a open stream reply message.
    ///
    /// # Safety
    ///
    /// The raw message must point to data that is valid for the lifetime of
    /// this message.
    unsafe fn from_open_stream_reply(value: sys::ksnp_msg_open_stream_reply) -> Self {
        match NonZero::new(value.code.0) {
            None => Self::OpenStreamReply {
                // SAFETY: A message with status 0 has a valid reply object
                parameters: StreamAcceptedParams::from_accepted_params(unsafe {
                    value.parameters.reply.as_ref().unwrap()
                }),
            },
            Some(code) => Self::OpenStreamFailed {
                code: code.into(),
                // SAFETY: A message with non-zero status has a no parameters or
                // a qos object.
                parameters: unsafe { value.parameters.qos.as_ref() }
                    .map(StreamQosParams::from_qos_params),
                // SAFETY: The message pointer is valid for the lifetime of the
                // message.
                message: unsafe { string_ref(value.message) },
            },
        }
    }

    /// Converts a message from a raw close stream notify message.
    ///
    /// # Safety
    ///
    /// The raw message must point to data that is valid for the lifetime of
    /// this message.
    unsafe fn from_close_stream_notify(value: sys::ksnp_msg_close_stream_notify) -> Self {
        Self::CloseStreamNotify {
            code: value.code,
            // SAFETY: The message pointer is valid for the lifetime of the
            // message.
            message: unsafe { string_ref(value.message) },
        }
    }

    /// Converts a message from a raw suspend stream reply message.
    ///
    /// # Safety
    ///
    /// The raw message must point to data that is valid for the lifetime of
    /// this message.
    unsafe fn from_suspend_stream_reply(value: sys::ksnp_msg_suspend_stream_reply) -> Self {
        match NonZero::new(value.code.0) {
            None => Self::SuspendStreamReply {
                timeout: Duration::from_secs(value.timeout.into()),
            },
            Some(code) => Self::SuspendStreamFailed {
                code: code.into(),
                // SAFETY: The message pointer is valid for the lifetime of the
                // message.
                message: unsafe { string_ref(value.message) },
            },
        }
    }

    /// Converts a message from a raw keep alive reply message.
    ///
    /// # Safety
    ///
    /// The raw message must point to data that is valid for the lifetime of
    /// this message.
    unsafe fn from_keep_alive_stream_reply(value: sys::ksnp_msg_keep_alive_stream_reply) -> Self {
        match NonZero::new(value.code.0) {
            None => Self::KeepAliveReply,
            Some(code) => Self::KeepAliveFailed {
                code: code.into(),
                // SAFETY: The message pointer is valid for the lifetime of the
                // message.
                message: unsafe { string_ref(value.message) },
            },
        }
    }

    /// Converts a message from a raw key data message.
    ///
    /// # Safety
    ///
    /// The raw message must point to data that is valid for the lifetime of
    /// this message.
    unsafe fn from_key_data_notify(value: sys::ksnp_msg_key_data_notify) -> Self {
        // The JSON parameters are ignored for now
        Self::KeyDataNotify {
            // SAFETY: A key data message points to valid key data.
            key_data: unsafe { slice::from_raw_parts(value.key_data.data, value.key_data.len) },
        }
    }

    /// Converts a message from a raw message.
    ///
    /// # Safety
    ///
    /// The raw message must point to data that is valid for the lifetime of this
    /// message.
    pub unsafe fn from_message(value: sys::ksnp_message) -> Option<Self> {
        // SAFETY: The union's type dictates which field is set.
        let message = unsafe {
            match value.type_ {
                sys::ksnp_message_type::KSNP_MSG_NONE => return None,
                sys::ksnp_message_type::KSNP_MSG_ERROR => Message::from(value.anon_1.error),
                sys::ksnp_message_type::KSNP_MSG_VERSION => Message::from(value.anon_1.version),
                sys::ksnp_message_type::KSNP_MSG_OPEN_STREAM => {
                    Message::from_open_stream(value.anon_1.open_stream)
                }
                sys::ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY => {
                    Message::from_open_stream_reply(value.anon_1.open_stream_reply)
                }
                sys::ksnp_message_type::KSNP_MSG_CLOSE_STREAM => {
                    Message::from(value.anon_1.close_stream)
                }
                sys::ksnp_message_type::KSNP_MSG_CLOSE_STREAM_REPLY => {
                    Message::from(value.anon_1.close_stream_reply)
                }
                sys::ksnp_message_type::KSNP_MSG_CLOSE_STREAM_NOTIFY => {
                    Message::from_close_stream_notify(value.anon_1.close_stream_notify)
                }
                sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM => {
                    Message::from(value.anon_1.suspend_stream)
                }
                sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY => {
                    Message::from_suspend_stream_reply(value.anon_1.suspend_stream_reply)
                }
                sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY => {
                    Message::from(value.anon_1.suspend_stream_notify)
                }
                sys::ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM => {
                    Message::from(value.anon_1.keep_alive_stream)
                }
                sys::ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY => {
                    Message::from_keep_alive_stream_reply(value.anon_1.keep_alive_stream_reply)
                }
                sys::ksnp_message_type::KSNP_MSG_CAPACITY_NOTIFY => {
                    Message::from(value.anon_1.capacity_notify)
                }
                sys::ksnp_message_type::KSNP_MSG_KEY_DATA_NOTIFY => {
                    Message::from_key_data_notify(value.anon_1.key_data_notify)
                }

                // ASSERT: The type must be one of constants of the message_type
                // enumeration.
                _ => unreachable!(),
            }
        };
        Some(message)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_read() {
        assert!(MessageContext::new().unwrap().want_read());
        assert!(!MessageContext::new().unwrap().want_write());
    }
}
