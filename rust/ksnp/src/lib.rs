#![doc=include_str!("../README.md")]
#![allow(missing_docs)]

mod client;
mod message;
mod processor;
mod server;
mod types;

pub use uuid::Uuid;

pub use ksnp_sys::{self as sys, ksnp_error};

pub use client::{ClientConnection, ClientEvent};
pub use message::{Message, MessageContext};
pub use processor::Processor;
pub use server::{ServerConnection, ServerEvent, Stream, StreamImpl};
pub use types::{Address, Qos, Rate, StreamAcceptedParams, StreamOpenParams, StreamQosParams};
