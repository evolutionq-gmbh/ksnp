use core::{
    ffi::CStr,
    fmt,
    num::{NonZero, TryFromIntError},
};

use crate::sys;

/// KSNP API error.
///
/// These errors are caused by the API being misused or not being able to get
/// some resource (such as memory). Notably, invalid messages from a remote do
/// not cause these errors, but rather [`ProtocolError`]s.
///
/// This type can be compared with the constants from [`sys::ksnp_error`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct Error(NonZero<u32>);

impl Error {
    /// Creates an instance of Self from the given error code. The error must be
    /// nonzero, i.e. indicate a true error and not match
    /// [`sys::ksnp_error::KSNP_E_NO_ERROR`].
    ///
    /// # Panics
    ///
    /// Panics if the [`sys::ksnp_error::KSNP_E_NO_ERROR`] constant is provided.
    pub fn from_error(err: sys::ksnp_error) -> Self {
        Self(err.0.try_into().unwrap())
    }
}

impl core::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(error_description(sys::ksnp_error(self.0.get())))
    }
}

impl TryFrom<sys::ksnp_error> for Error {
    type Error = TryFromIntError;

    fn try_from(value: sys::ksnp_error) -> Result<Self, Self::Error> {
        // ksnp_error::KSNP_E_NO_ERROR is the 0 value, so NonZero will map
        // appropriately.
        Ok(Self(value.0.try_into()?))
    }
}

impl From<Error> for sys::ksnp_error {
    fn from(value: Error) -> Self {
        Self(value.0.get())
    }
}

impl PartialEq<sys::ksnp_error> for Error {
    fn eq(&self, other: &sys::ksnp_error) -> bool {
        self.0.get() == other.0
    }
}

/// Error in the KSNP protocol state machine.
///
/// These errors occur when invalid or unexpected messages are being send, or
/// those messages containing invalid values.
///
/// This type can be compared with the constants from [`sys::ksnp_error_code`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct ProtocolError(sys::ksnp_error_code);

impl core::error::Error for ProtocolError {}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(protocol_error_description(self.0))
    }
}

impl From<sys::ksnp_error_code> for ProtocolError {
    fn from(value: sys::ksnp_error_code) -> Self {
        Self(value)
    }
}

impl From<ProtocolError> for sys::ksnp_error_code {
    fn from(value: ProtocolError) -> Self {
        value.0
    }
}

impl PartialEq<sys::ksnp_error_code> for ProtocolError {
    fn eq(&self, other: &sys::ksnp_error_code) -> bool {
        self.0.0 == other.0
    }
}

/// Result for KSNP operations.
///
/// Remote KSNP operations that can succeed or fail without triggering a
/// protocol error use a status code to indicate success, wrapped by this type.
///
/// This code may indicate success or failure. See also [`FailedReason`] for
/// a type wrapping status codes indicating failure.
///
/// This type can be compared with the constants from [`sys::ksnp_status_code`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct StatusCode(sys::ksnp_status_code);

impl fmt::Display for StatusCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(status_code_description(self.0))
    }
}

impl From<sys::ksnp_status_code> for StatusCode {
    fn from(value: sys::ksnp_status_code) -> Self {
        Self(value)
    }
}

impl From<StatusCode> for sys::ksnp_status_code {
    fn from(value: StatusCode) -> Self {
        value.0
    }
}

impl From<FailedReason> for StatusCode {
    fn from(value: FailedReason) -> Self {
        Self(sys::ksnp_status_code(value.0.get()))
    }
}

impl PartialEq<sys::ksnp_status_code> for StatusCode {
    fn eq(&self, other: &sys::ksnp_status_code) -> bool {
        self.0.0 == other.0
    }
}

/// Reason for failed KSNP operations.
///
/// Remote KSNP operations that fail indicate the reason of failure using this
/// type. See also [`StatusCode`] for a type wrapping status codes indicating
/// either success or failure.
///
/// This type can be compared with the constants from [`sys::ksnp_status_code`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct FailedReason(NonZero<u32>);

impl core::error::Error for FailedReason {}

impl fmt::Display for FailedReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(status_code_description(sys::ksnp_status_code(self.0.get())))
    }
}

impl From<NonZero<u32>> for FailedReason {
    fn from(value: NonZero<u32>) -> Self {
        Self(value)
    }
}

impl TryFrom<sys::ksnp_status_code> for FailedReason {
    type Error = TryFromIntError;

    fn try_from(value: sys::ksnp_status_code) -> Result<Self, Self::Error> {
        // ksnp_status_code::KSNP_STATUS_SUCCESS is the 0 value, so NonZero will
        // map appropriately.
        Ok(Self(value.0.try_into()?))
    }
}

impl TryFrom<StatusCode> for FailedReason {
    type Error = TryFromIntError;

    fn try_from(value: StatusCode) -> Result<Self, Self::Error> {
        Self::try_from(value.0)
    }
}

impl From<FailedReason> for sys::ksnp_status_code {
    fn from(value: FailedReason) -> Self {
        Self(value.0.get())
    }
}

impl PartialEq<sys::ksnp_status_code> for FailedReason {
    fn eq(&self, other: &sys::ksnp_status_code) -> bool {
        self.0.get() == other.0
    }
}

/// Checks if the given [`sys::ksnp_error`] value indicates an error.
///
/// Returns a [`Result`] based on the given value.
pub(crate) fn check_err(err: sys::ksnp_error) -> Result<(), Error> {
    match NonZero::new(err.0) {
        None => Ok(()),
        Some(err) => Err(Error(err)),
    }
}

/// Gets a description for an API error.
pub fn error_description(err: sys::ksnp_error) -> &'static str {
    // SAFETY: KSNP will accept any error code as input, it is just that the
    // output may not make sense if out of range.
    let str = unsafe { sys::ksnp_error_description(err) };
    // ASSERT: KSNP error descriptions are valid UTF-8 (ASCII, even).
    // SAFETY: KSNP will return valid static string pointers.
    unsafe { CStr::from_ptr(str) }.to_str().unwrap()
}

/// Gets a description for a message status code.
pub fn status_code_description(err: sys::ksnp_status_code) -> &'static str {
    // SAFETY: KSNP will accept any status code as input, it is just that the
    // output may not make sense if out of range.
    let str = unsafe { sys::ksnp_status_code_description(err) };
    // ASSERT: KSNP status descriptions are valid UTF-8 (ASCII, even).
    // SAFETY: KSNP will return valid static string pointers.
    unsafe { CStr::from_ptr(str) }.to_str().unwrap()
}

/// Gets a description for a protocol error.
pub fn protocol_error_description(err: sys::ksnp_error_code) -> &'static str {
    // SAFETY: KSNP will accept any protocol error code as input, it is just
    // that the output may not make sense if out of range.
    let str = unsafe { sys::ksnp_protocol_error_description(err) };
    // ASSERT: KSNP protocol error descriptions are valid UTF-8 (ASCII, even).
    // SAFETY: KSNP will return valid static string pointers.
    unsafe { CStr::from_ptr(str) }.to_str().unwrap()
}
