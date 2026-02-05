#![doc=include_str!("../README.md")]
#![allow(missing_docs)]

mod client;
mod error;
mod message;
mod processor;
mod server;
mod types;

pub use uuid::Uuid;

pub use ksnp_sys as sys;

pub use client::{ClientConnection, ClientEvent};
pub use error::{
    Error, FailedReason, ProtocolError, StatusCode, error_description, protocol_error_description,
    status_code_description,
};
pub use message::{Buffer, BufferImpl, Message, MessageContext};
pub use processor::Processor;
pub use server::{ServerConnection, ServerEvent, Stream, StreamImpl};
pub use types::{
    Address, CloseDirection, Qos, Rate, StreamAcceptedParams, StreamOpenParams, StreamQosParams,
};
