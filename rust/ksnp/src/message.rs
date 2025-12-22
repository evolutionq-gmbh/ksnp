use core::{
    any::Any,
    ffi::{CStr, c_uchar},
    mem::MaybeUninit,
    num::NonZero,
    pin::Pin,
    ptr::{self, null, null_mut},
    slice,
    time::Duration,
};

use uuid::Uuid;

use crate::{
    sys::{self, ksnp_error},
    types::{StreamAcceptedParams, StreamOpenParams, StreamQosParams, map_err, string_ref},
};

pub trait BufferImpl: Any + Unpin {
    /// Return the data stored currently in the buffer
    fn data(&mut self) -> &mut [u8];

    /// Returns the size of the buffer.
    fn size(&self) -> usize;

    fn consume(&mut self, count: usize);

    fn append(&mut self, data: &[u8]) -> Result<(), ksnp_error>;

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

impl<T: BufferImpl> Buffer<T> {
    const BASE_OFFSET: usize = core::mem::offset_of!(Self, base);

    /// Converts a raw stream pointer to a self reference.
    ///
    /// # Safety
    ///
    /// The pointer must have been created from the address of Self::base, and
    /// point into a valid instance of self. Furthermore, the lifetime of the
    /// resulting reference may not exceed that of the given pointer.
    unsafe fn buffer_to_self<'a>(buffer: *const sys::ksnp_buffer) -> &'a Self {
        // SAFETY: The stream parameter points to an instance of Self::base,
        // so the self pointer is found by subtracting the base offset.
        unsafe { buffer.byte_sub(Self::BASE_OFFSET).cast::<Self>().as_ref() }.unwrap()
    }

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
                data: Some(Self::data),
                size: Some(Self::size),
                consume: Some(Self::consume),
                append: Some(Self::append),
                truncate: Some(Self::truncate),
            },
            this,
        }
    }

    extern "C" fn data(buffer: *mut sys::ksnp_buffer) -> *mut c_uchar {
        // SAFETY: The buffer parameter points to an instance of Self::base, as
        // only the base's data method can call here.
        unsafe { Self::buffer_to_self_mut(buffer) }
            .this
            .data()
            .as_mut_ptr()
    }

    extern "C" fn size(buffer: *mut sys::ksnp_buffer) -> usize {
        // SAFETY: The buffer parameter points to an instance of Self::base, as
        // only the base's size method can call here.
        unsafe { Self::buffer_to_self(buffer) }.this.size()
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
        len: usize,
    ) -> ksnp_error {
        // SAFETY: The buffer parameter points to an instance of Self::base, as
        // only the base's size method can call here.
        match unsafe { Self::buffer_to_self_mut(buffer) }
            .this
            // SAFETY: The input buffer points to valid data.
            .append(unsafe { slice::from_raw_parts(data, len) })
        {
            Ok(()) => ksnp_error::KSNP_E_NO_ERROR,
            Err(e) => e,
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

    fn append(&mut self, data: &[u8]) -> Result<(), ksnp_error> {
        if self.try_reserve(data.len()).is_err() {
            return Err(ksnp_error::KSNP_E_NO_MEM);
        }
        self.extend_from_slice(data);
        Ok(())
    }

    fn truncate(&mut self, count: usize) {
        self.truncate(count);
    }
}

/// Wrapper for a [`sys::ksnp_message_context`].
pub struct MessageContext {
    pub(crate) ctx: *mut sys::ksnp_message_context,
    read_buffer: Option<Pin<Box<Buffer<dyn BufferImpl>>>>,
    write_buffer: Option<Pin<Box<Buffer<dyn BufferImpl>>>>,
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
    pub fn new() -> Option<Self> {
        let mut ctx: *mut sys::ksnp_message_context = null_mut();
        // SAFETY: ctx is a valid writeable pointer.
        unsafe { sys::ksnp_message_context_create(&raw mut ctx) };
        if ctx.is_null() {
            None
        } else {
            Some(Self {
                ctx,
                read_buffer: None,
                write_buffer: None,
            })
        }
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
    ) -> Option<Self> {
        let read_buffer = Box::pin(Buffer::new(read_buffer));
        let write_buffer = Box::pin(Buffer::new(write_buffer));

        let mut ctx: *mut sys::ksnp_message_context = null_mut();
        // SAFETY: ctx is a valid writeable pointer. The buffer pointers will
        // not move since they are contained by Arc.
        unsafe {
            sys::ksnp_message_context_create_with_buffer(
                &raw mut ctx,
                read_buffer.buffer_ptr(),
                write_buffer.buffer_ptr(),
            )
        };
        if ctx.is_null() {
            None
        } else {
            Some(Self {
                ctx,
                read_buffer: Some(read_buffer),
                write_buffer: Some(write_buffer),
            })
        }
    }

    /// Gets a reference to the read buffer that was using when this context was
    /// constructed.
    ///
    /// The resulting reference can be downcast to a concrete type using the
    /// [`Any`] trait.
    ///
    /// If no read buffer was specified, returns None.
    pub fn read_buf(&self) -> Option<&dyn BufferImpl> {
        self.read_buffer.as_deref().map(Buffer::buffer_impl)
    }

    /// Gets a mutable reference to the read buffer that was using when this
    /// context was constructed.
    ///
    /// The resulting reference can be downcast to a concrete type using the
    /// [`Any`] trait.
    ///
    /// If no read buffer was specified, returns None.
    pub fn read_buf_mut(&mut self) -> Option<&mut dyn BufferImpl> {
        self.read_buffer.as_deref_mut().map(Buffer::buffer_impl_mut)
    }

    /// Gets a reference to the write buffer that was using when this context
    /// was constructed.
    ///
    /// The resulting reference can be downcast to a concrete type using the
    /// [`Any`] trait.
    ///
    /// If no write buffer was specified, returns None.
    pub fn write_buf(&self) -> Option<&dyn BufferImpl> {
        self.write_buffer.as_deref().map(Buffer::buffer_impl)
    }

    /// Gets a mutable reference to the write buffer that was using when this
    /// context was constructed.
    ///
    /// The resulting reference can be downcast to a concrete type using the
    /// [`Any`] trait.
    ///
    /// If no write buffer was specified, returns None.
    pub fn write_buf_mut(&mut self) -> Option<&mut dyn BufferImpl> {
        self.write_buffer
            .as_deref_mut()
            .map(Buffer::buffer_impl_mut)
    }

    /// Writes the given message into the write buffer used by the context.
    pub fn write_message(&mut self, message: Message<'_>) -> Result<(), ksnp_error> {
        let mut scratch = None;
        // SAFETY: The pointers inside the message are valid for the duration of
        // this call, as the argument stays valid. The scratch space is not
        // modified by this function.
        let message = unsafe { message.try_to_sys(&mut scratch) }?;
        // SAFETY: The message and scratch space are valid for the duration of
        // this call and not modified.
        map_err(unsafe { sys::ksnp_message_context_write_message(self.ctx, &raw const message) })?;
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
    pub fn read_data(&mut self, data: &[u8]) -> Result<usize, ksnp_error> {
        let mut len = data.len();
        // SAFETY: self.ctx is valid for the lifetime of this wrapper, the
        // buffer and size pointers are derived from valid instances, len is
        // initialized properly.
        map_err(unsafe {
            sys::ksnp_message_context_read_data(self.ctx, data.as_ptr(), &raw mut len)
        })?;
        Ok(len)
    }

    /// Writes the stored data into the given buffer.
    ///
    /// Returns the number of bytes written.
    pub fn write_data(&mut self, data: &mut [MaybeUninit<u8>]) -> Result<usize, ksnp_error> {
        let mut len = data.len();
        // SAFETY: self.ctx is valid for the lifetime of this wrapper, the
        // buffer and size pointers are derived from valid instances, len is
        // initialized properly.
        map_err(unsafe {
            sys::ksnp_message_context_write_data(
                self.ctx,
                data.as_mut_ptr().cast::<u8>(),
                &raw mut len,
            )
        })?;
        Ok(len)
    }

    /// Returns the next message event, if any.
    pub fn next_event(&mut self) -> Result<MessageResult<'_>, ksnp_error> {
        let mut value = null();
        let mut protocol_error = sys::ksnp_protocol_error {
            code: sys::ksnp_error_code::KSNP_PROT_E_UNKNOWN_ERROR,
            description: null(),
        };
        // SAFETY: self.ctx is valid for the lifetime of this wrapper, the value
        // pointer is writeable.
        match map_err(unsafe {
            sys::ksnp_message_context_next_message(
                self.ctx,
                &raw mut value,
                &raw mut protocol_error,
            )
        }) {
            Ok(()) => {
                // SAFETY: The pointer is valid until the underlying context is
                // modified. The exclusive borrow on self ensures this.
                let msg = MessageResult::from(unsafe { value.as_ref() }.map(Message::from));
                Ok(msg)
            }
            Err(ksnp_error::KSNP_E_PROTOCOL_ERROR) => {
                Ok(MessageResult::ProtocolError {
                    code: protocol_error.code.0,
                    // SAFETY: The description is valid as long as this context is
                    // not modified, which it can't due to the exclusive reference.
                    description: unsafe { string_ref(protocol_error.description) },
                })
            }
            Err(e) => Err(e),
        }
    }
}

#[derive(Debug)]
pub enum Message<'ctx> {
    Error {
        code: u32,
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
        code: NonZero<u32>,
        parameters: Option<StreamQosParams<'ctx>>,
        message: Option<&'ctx CStr>,
    },
    CloseStream,
    CloseStreamReply,
    CloseStreamNotify {
        code: u32,
        message: Option<&'ctx CStr>,
    },
    SuspendStream {
        timeout: Duration,
    },
    SuspendStreamReply {
        timeout: Duration,
    },
    SuspendStreamFailed {
        code: NonZero<u32>,
        message: Option<&'ctx CStr>,
    },
    SuspendStreamNotify {
        code: u32,
        timeout: Duration,
    },
    KeepAlive {
        stream_id: Uuid,
    },
    KeepAliveReply,
    KeepAliveFailed {
        code: NonZero<u32>,
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
        code: u32,
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
    ) -> Result<sys::ksnp_message, ksnp_error> {
        let msg = match self {
            &Self::Error { code } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_ERROR,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    error: sys::ksnp_msg_error {
                        code: ksnp_sys::ksnp_error_code(code),
                    },
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
                            code: sys::ksnp_status_code(code.get()),
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
                        code: sys::ksnp_status_code(code),
                        message: message.map_or(null(), CStr::as_ptr),
                    },
                },
            },
            &Self::SuspendStream { timeout } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    suspend_stream: sys::ksnp_msg_suspend_stream {
                        timeout: timeout
                            .as_secs()
                            .try_into()
                            .map_err(|_| ksnp_error::KSNP_E_INVALID_ARGUMENT)?,
                    },
                },
            },
            &Self::SuspendStreamReply { timeout } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    suspend_stream_reply: sys::ksnp_msg_suspend_stream_reply {
                        code: sys::ksnp_status_code::KSNP_STATUS_SUCCESS,
                        timeout: timeout
                            .as_secs()
                            .try_into()
                            .map_err(|_| ksnp_error::KSNP_E_INVALID_ARGUMENT)?,
                        message: null(),
                    },
                },
            },
            &Self::SuspendStreamFailed { code, message } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    suspend_stream_reply: sys::ksnp_msg_suspend_stream_reply {
                        code: sys::ksnp_status_code(code.get()),
                        timeout: 0,
                        message: message.map_or(null(), CStr::as_ptr),
                    },
                },
            },
            &Self::SuspendStreamNotify { code, timeout } => sys::ksnp_message {
                type_: sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY,
                anon_1: sys::ksnp_message__bindgen_ty_1 {
                    suspend_stream_notify: sys::ksnp_msg_suspend_stream_notify {
                        code: sys::ksnp_status_code(code),
                        timeout: timeout
                            .as_secs()
                            .try_into()
                            .map_err(|_| ksnp_error::KSNP_E_INVALID_ARGUMENT)?,
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
                        code: sys::ksnp_status_code(code.get()),
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
                        key_data: sys::ksnp_data {
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

impl From<&sys::ksnp_msg_error> for Message<'_> {
    fn from(value: &sys::ksnp_msg_error) -> Self {
        Self::Error { code: value.code.0 }
    }
}

impl From<&sys::ksnp_msg_version> for Message<'_> {
    fn from(value: &sys::ksnp_msg_version) -> Self {
        Self::Version {
            minimum_version: value.minimum_version.0,
            maximum_version: value.maximum_version.0,
        }
    }
}

impl From<&sys::ksnp_msg_open_stream> for Message<'_> {
    fn from(value: &sys::ksnp_msg_open_stream) -> Self {
        Self::OpenStream {
            // SAFETY: The input message must point to a valid parameters
            // object.
            parameters: StreamOpenParams::from_open_params(unsafe {
                value.parameters.as_ref().unwrap()
            }),
        }
    }
}

impl From<&sys::ksnp_msg_open_stream_reply> for Message<'_> {
    fn from(value: &sys::ksnp_msg_open_stream_reply) -> Self {
        match NonZero::new(value.code.0) {
            None => Self::OpenStreamReply {
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
                // message.
                message: unsafe { string_ref(value.message) },
            },
        }
    }
}

impl From<&sys::ksnp_msg_close_stream> for Message<'_> {
    fn from(_value: &sys::ksnp_msg_close_stream) -> Self {
        Self::CloseStream
    }
}

impl From<&sys::ksnp_msg_close_stream_reply> for Message<'_> {
    fn from(_value: &sys::ksnp_msg_close_stream_reply) -> Self {
        Self::CloseStreamReply
    }
}

impl From<&sys::ksnp_msg_close_stream_notify> for Message<'_> {
    fn from(value: &sys::ksnp_msg_close_stream_notify) -> Self {
        Self::CloseStreamNotify {
            code: value.code.0,
            // SAFETY: The message pointer is valid for the lifetime of the
            // message.
            message: unsafe { string_ref(value.message) },
        }
    }
}

impl From<&sys::ksnp_msg_suspend_stream> for Message<'_> {
    fn from(value: &sys::ksnp_msg_suspend_stream) -> Self {
        Self::SuspendStream {
            timeout: Duration::from_secs(value.timeout.into()),
        }
    }
}

impl From<&sys::ksnp_msg_suspend_stream_reply> for Message<'_> {
    fn from(value: &sys::ksnp_msg_suspend_stream_reply) -> Self {
        match NonZero::new(value.code.0) {
            None => Self::SuspendStreamReply {
                timeout: Duration::from_secs(value.timeout.into()),
            },
            Some(code) => Self::SuspendStreamFailed {
                code,
                // SAFETY: The message pointer is valid for the lifetime of the
                // message.
                message: unsafe { string_ref(value.message) },
            },
        }
    }
}

impl From<&sys::ksnp_msg_suspend_stream_notify> for Message<'_> {
    fn from(value: &sys::ksnp_msg_suspend_stream_notify) -> Self {
        Self::SuspendStreamNotify {
            code: value.code.0,
            timeout: Duration::from_secs(value.timeout.into()),
        }
    }
}

impl From<&sys::ksnp_msg_keep_alive_stream> for Message<'_> {
    fn from(value: &sys::ksnp_msg_keep_alive_stream) -> Self {
        Self::KeepAlive {
            stream_id: Uuid::from_bytes(value.key_stream_id),
        }
    }
}

impl From<&sys::ksnp_msg_keep_alive_stream_reply> for Message<'_> {
    fn from(value: &sys::ksnp_msg_keep_alive_stream_reply) -> Self {
        match NonZero::new(value.code.0) {
            None => Self::KeepAliveReply,
            Some(code) => Self::KeepAliveFailed {
                code,
                // SAFETY: The message pointer is valid for the lifetime of the
                // message.
                message: unsafe { string_ref(value.message) },
            },
        }
    }
}

impl From<&sys::ksnp_msg_capacity_notify> for Message<'_> {
    fn from(value: &sys::ksnp_msg_capacity_notify) -> Self {
        Self::CapacityNotify {
            additional_capacity: value.additional_capacity,
        }
    }
}

impl From<&sys::ksnp_msg_key_data_notify> for Message<'_> {
    fn from(value: &sys::ksnp_msg_key_data_notify) -> Self {
        // The JSON parameters are ignored for now
        Self::KeyDataNotify {
            // SAFETY: A key data message points to valid key data.
            key_data: unsafe { slice::from_raw_parts(value.key_data.data, value.key_data.len) },
        }
    }
}

impl<'ctx> From<&'ctx sys::ksnp_message> for Message<'ctx> {
    fn from(value: &'ctx sys::ksnp_message) -> Self {
        // SAFETY: The union's type dictates which field is set.
        unsafe {
            match value.type_ {
                sys::ksnp_message_type::KSNP_MSG_ERROR => Message::from(&value.anon_1.error),
                sys::ksnp_message_type::KSNP_MSG_VERSION => Message::from(&value.anon_1.version),
                sys::ksnp_message_type::KSNP_MSG_OPEN_STREAM => {
                    Message::from(&value.anon_1.open_stream)
                }
                sys::ksnp_message_type::KSNP_MSG_OPEN_STREAM_REPLY => {
                    Message::from(&value.anon_1.open_stream_reply)
                }
                sys::ksnp_message_type::KSNP_MSG_CLOSE_STREAM => {
                    Message::from(&value.anon_1.close_stream)
                }
                sys::ksnp_message_type::KSNP_MSG_CLOSE_STREAM_REPLY => {
                    Message::from(&value.anon_1.close_stream_reply)
                }
                sys::ksnp_message_type::KSNP_MSG_CLOSE_STREAM_NOTIFY => {
                    Message::from(&value.anon_1.close_stream_notify)
                }
                sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM => {
                    Message::from(&value.anon_1.suspend_stream)
                }
                sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_REPLY => {
                    Message::from(&value.anon_1.suspend_stream_reply)
                }
                sys::ksnp_message_type::KSNP_MSG_SUSPEND_STREAM_NOTIFY => {
                    Message::from(&value.anon_1.suspend_stream_notify)
                }
                sys::ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM => {
                    Message::from(&value.anon_1.keep_alive_stream)
                }
                sys::ksnp_message_type::KSNP_MSG_KEEP_ALIVE_STREAM_REPLY => {
                    Message::from(&value.anon_1.keep_alive_stream_reply)
                }
                sys::ksnp_message_type::KSNP_MSG_CAPACITY_NOTIFY => {
                    Message::from(&value.anon_1.capacity_notify)
                }
                sys::ksnp_message_type::KSNP_MSG_KEY_DATA_NOTIFY => {
                    Message::from(&value.anon_1.key_data_notify)
                }

                // ASSERT: The type must be one of constants of the message_type
                // enumeration.
                _ => unreachable!(),
            }
        }
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
