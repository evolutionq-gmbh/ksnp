use core::{
    cmp::Ordering,
    ffi::{CStr, c_char},
    marker::PhantomData,
    num::NonZero,
    ptr::null,
    slice,
};

use uuid::Uuid;

use crate::sys;

pub(crate) fn map_err(err: sys::ksnp_error) -> Result<(), sys::ksnp_error> {
    match err {
        sys::ksnp_error(0) => Ok(()),
        sys::ksnp_error(err) => Err(sys::ksnp_error(err)),
    }
}

pub(crate) unsafe fn string_ref<'msg>(message: *const c_char) -> Option<&'msg CStr> {
    if message.is_null() {
        None
    } else {
        // SAFETY: The message, if set, points to a valid CString.
        Some(unsafe { CStr::from_ptr(message) })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Address<'evt> {
    pub sae: &'evt CStr,
    pub network: Option<&'evt CStr>,
}

impl Address<'_> {
    /// Converts a raw address into an Address.
    pub(crate) fn from_address(address: &sys::ksnp_address) -> Option<Self> {
        if address.sae.is_null() {
            None
        } else {
            Some(Self {
                // ASSERT: non-null check of sae is above.
                // SAFETY: The string pointer is valid for the lifetime of the
                // enclosing address.
                sae: unsafe { string_ref(address.sae).unwrap() },
                // SAFETY: The string pointer is valid for the lifetime of the
                // enclosing address.
                network: unsafe { string_ref(address.network) },
            })
        }
    }

    pub(crate) unsafe fn as_sys(&self) -> sys::ksnp_address {
        sys::ksnp_address {
            sae: self.sae.as_ptr(),
            network: self.network.map_or(null(), CStr::as_ptr),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
// This type must match sys::ksnp_rate in layout for Qos parameters.
#[repr(C)]
pub struct Rate {
    pub bits: NonZero<u32>,
    pub seconds: Option<NonZero<u32>>,
}

impl Rate {
    pub(crate) fn from_rate(value: sys::ksnp_rate) -> Option<Self> {
        let bits = NonZero::new(value.bits)?;
        Some(Self {
            bits,
            seconds: NonZero::new(value.seconds),
        })
    }

    pub(crate) fn into_sys(self) -> sys::ksnp_rate {
        sys::ksnp_rate {
            bits: self.bits.get(),
            seconds: self.seconds.map_or(0, NonZero::get),
        }
    }
}

impl PartialOrd for Rate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Rate {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.bits.get() * other.seconds.map_or(1, NonZero::get))
            .cmp(&(other.bits.get() * self.seconds.map_or(1, NonZero::get)))
    }
}

#[derive(Debug)]
pub struct StreamOpenParams<'evt> {
    pub stream_id: Option<Uuid>,
    pub source: Option<Address<'evt>>,
    pub destination: Address<'evt>,
    pub chunk_size: Option<NonZero<u16>>,
    pub capacity: Option<NonZero<u32>>,
    pub min_bps: Option<Rate>,
    pub max_bps: Option<Rate>,
    pub ttl: Option<NonZero<u32>>,
    pub provision_size: Option<NonZero<u32>>,
    pub extensions: *mut sys::json_object,
    pub required_extensions: *mut sys::json_object,
}

impl<'evt> StreamOpenParams<'evt> {
    pub fn from_open_params(params: &'evt sys::ksnp_stream_open_params) -> Self {
        let stream_id = Uuid::from_bytes(params.stream_id);

        Self {
            stream_id: (!stream_id.is_nil()).then_some(stream_id),
            // SAFETY: The pointers are valid for the lifetime of this object as
            // dictated by this method's requirements.
            source: Address::from_address(&params.source),
            // ASSERT: destination is required for open stream.
            // SAFETY: The pointers are valid for the lifetime of this object as
            // dictated by this method's requirements.
            destination: Address::from_address(&params.destination).unwrap(),
            chunk_size: NonZero::new(params.chunk_size),
            capacity: NonZero::new(params.capacity),
            min_bps: Rate::from_rate(params.min_bps),
            max_bps: Rate::from_rate(params.max_bps),
            ttl: NonZero::new(params.ttl),
            provision_size: NonZero::new(params.provision_size),
            extensions: params.extensions,
            required_extensions: params.required_extensions,
        }
    }

    /// Converts this parameters object into a library object.
    ///
    /// #Safety
    ///
    /// The pointers inside the resulting object are valid only for as long as
    /// this object is not modified.
    pub(crate) unsafe fn to_sys(&self) -> sys::ksnp_stream_open_params {
        sys::ksnp_stream_open_params {
            stream_id: self
                .stream_id
                .map_or(Uuid::nil().into_bytes(), Uuid::into_bytes),
            source: self.source.map_or(
                sys::ksnp_address {
                    sae: null(),
                    network: null(),
                },
                // SAFETY: The pointers point into this parameters object, and
                // are valid as specified by this method's documentation.
                |a| unsafe { a.as_sys() },
            ),
            // SAFETY: The pointers point into this parameters object, and are
            // valid as specified by this method's documentation.
            destination: unsafe { self.destination.as_sys() },
            chunk_size: self.chunk_size.map_or(0, NonZero::get),
            capacity: self.capacity.map_or(0, NonZero::get),
            min_bps: self.min_bps.map_or(
                sys::ksnp_rate {
                    bits: 0,
                    seconds: 0,
                },
                Rate::into_sys,
            ),
            max_bps: self.max_bps.map_or(
                sys::ksnp_rate {
                    bits: 0,
                    seconds: 0,
                },
                Rate::into_sys,
            ),
            ttl: self.ttl.map_or(0, NonZero::get),
            provision_size: self.provision_size.map_or(0, NonZero::get),
            extensions: self.extensions,
            required_extensions: self.required_extensions,
        }
    }
}

#[derive(Debug)]
pub struct StreamAcceptedParams<'evt> {
    pub stream_id: Option<Uuid>,
    pub chunk_size: Option<NonZero<u16>>,
    pub position: Option<NonZero<u32>>,
    pub max_key_delay: Option<NonZero<u32>>,
    pub min_bps: Rate,
    pub provision_size: Option<NonZero<u32>>,
    pub extensions: *mut sys::json_object,
    pub _ptr_lifetime: PhantomData<&'evt sys::json_object>,
}

impl<'evt> StreamAcceptedParams<'evt> {
    pub fn from_accepted_params(params: &'evt sys::ksnp_stream_accepted_params) -> Self {
        let stream_id = Uuid::from_bytes(params.stream_id);

        Self {
            stream_id: (!stream_id.is_nil()).then_some(stream_id),
            chunk_size: NonZero::new(params.chunk_size),
            position: NonZero::new(params.position),
            max_key_delay: NonZero::new(params.max_key_delay),
            // ASSERT: The min_bps field is required for accepted stream parameters.
            min_bps: Rate::from_rate(params.min_bps).unwrap(),
            provision_size: NonZero::new(params.provision_size),
            extensions: params.extensions,
            _ptr_lifetime: PhantomData,
        }
    }

    pub(crate) unsafe fn to_sys(&self) -> sys::ksnp_stream_accepted_params {
        sys::ksnp_stream_accepted_params {
            stream_id: self
                .stream_id
                .map_or(Uuid::nil().into_bytes(), Uuid::into_bytes),
            chunk_size: self.chunk_size.map_or(0, NonZero::get),
            position: self.position.map_or(0, NonZero::get),
            max_key_delay: self.max_key_delay.map_or(0, NonZero::get),
            min_bps: self.min_bps.into_sys(),
            provision_size: self.provision_size.map_or(0, NonZero::get),
            extensions: self.extensions,
        }
    }
}

#[derive(Debug)]
pub enum Qos<'val, T> {
    Empty,
    List(&'val [T]),
    Range { min: T, max: T },
}

impl Qos<'_, u16> {
    pub(crate) const NONE: sys::ksnp_qos_u16 = sys::ksnp_qos_u16 {
        type_: sys::ksnp_qos_type::KSNP_QOS_NONE,
        anon_1: sys::ksnp_qos_u16__bindgen_ty_1 { none: 0 },
    };

    pub(crate) fn from_qos(value: &sys::ksnp_qos_u16) -> Option<Self> {
        let this = match value.type_ {
            sys::ksnp_qos_type::KSNP_QOS_NONE => return None,
            sys::ksnp_qos_type::KSNP_QOS_NULL => Self::Empty,
            sys::ksnp_qos_type::KSNP_QOS_LIST => {
                // SAFETY: QOS_LIST means the list member is set.
                let list = unsafe { value.anon_1.list };
                // SAFETY: The values pointer is valid for the lifetime of the
                // list and layout compatible.
                Self::List(unsafe { slice::from_raw_parts(list.values, list.count) })
            }
            sys::ksnp_qos_type::KSNP_QOS_RANGE => {
                // SAFETY: QOS_RANGE means the range member is set.
                let range = unsafe { value.anon_1.range };
                Self::Range {
                    min: range.min,
                    max: range.max,
                }
            }
            // ASSERT: Only the enumerated QoS types are valid.
            _ => unreachable!(),
        };
        Some(this)
    }

    pub(crate) fn to_sys(&self) -> sys::ksnp_qos_u16 {
        match self {
            Self::Empty => sys::ksnp_qos_u16 {
                type_: sys::ksnp_qos_type::KSNP_QOS_NULL,
                anon_1: sys::ksnp_qos_u16__bindgen_ty_1 { none: 0 },
            },
            &Self::List(list) => sys::ksnp_qos_u16 {
                type_: sys::ksnp_qos_type::KSNP_QOS_LIST,
                anon_1: sys::ksnp_qos_u16__bindgen_ty_1 {
                    list: sys::ksnp_qos_list_u16 {
                        values: list.as_ptr(),
                        count: list.len(),
                    },
                },
            },
            &Self::Range { min, max } => sys::ksnp_qos_u16 {
                type_: sys::ksnp_qos_type::KSNP_QOS_RANGE,
                anon_1: sys::ksnp_qos_u16__bindgen_ty_1 {
                    range: sys::ksnp_qos_range_u16 { min, max },
                },
            },
        }
    }
}

impl Qos<'_, u32> {
    pub(crate) const NONE: sys::ksnp_qos_u32 = sys::ksnp_qos_u32 {
        type_: sys::ksnp_qos_type::KSNP_QOS_NONE,
        anon_1: sys::ksnp_qos_u32__bindgen_ty_1 { none: 0 },
    };

    pub(crate) fn from_qos(value: &sys::ksnp_qos_u32) -> Option<Self> {
        let this = match value.type_ {
            sys::ksnp_qos_type::KSNP_QOS_NONE => return None,
            sys::ksnp_qos_type::KSNP_QOS_NULL => Self::Empty,
            sys::ksnp_qos_type::KSNP_QOS_LIST => {
                // SAFETY: QOS_LIST means the list member is set.
                let list = unsafe { value.anon_1.list };
                // SAFETY: The values pointer is valid for the lifetime of the
                // list and layout compatible.
                Self::List(unsafe { slice::from_raw_parts(list.values, list.count) })
            }
            sys::ksnp_qos_type::KSNP_QOS_RANGE => {
                // SAFETY: QOS_RANGE means the range member is set.
                let range = unsafe { value.anon_1.range };
                Self::Range {
                    min: range.min,
                    max: range.max,
                }
            }
            // ASSERT: Only the enumerated QoS types are valid.
            _ => unreachable!(),
        };
        Some(this)
    }

    pub(crate) fn to_sys(&self) -> sys::ksnp_qos_u32 {
        match self {
            Self::Empty => sys::ksnp_qos_u32 {
                type_: sys::ksnp_qos_type::KSNP_QOS_NULL,
                anon_1: sys::ksnp_qos_u32__bindgen_ty_1 { none: 0 },
            },
            &Self::List(list) => sys::ksnp_qos_u32 {
                type_: sys::ksnp_qos_type::KSNP_QOS_LIST,
                anon_1: sys::ksnp_qos_u32__bindgen_ty_1 {
                    list: sys::ksnp_qos_list_u32 {
                        values: list.as_ptr(),
                        count: list.len(),
                    },
                },
            },
            &Self::Range { min, max } => sys::ksnp_qos_u32 {
                type_: sys::ksnp_qos_type::KSNP_QOS_RANGE,
                anon_1: sys::ksnp_qos_u32__bindgen_ty_1 {
                    range: sys::ksnp_qos_range_u32 { min, max },
                },
            },
        }
    }
}

impl Qos<'_, Rate> {
    pub(crate) const NONE: sys::ksnp_qos_rate = sys::ksnp_qos_rate {
        type_: sys::ksnp_qos_type::KSNP_QOS_NONE,
        anon_1: sys::ksnp_qos_rate__bindgen_ty_1 { none: 0 },
    };

    pub(crate) fn from_qos(value: &sys::ksnp_qos_rate) -> Option<Self> {
        let this = match value.type_ {
            sys::ksnp_qos_type::KSNP_QOS_NONE | sys::ksnp_qos_type::KSNP_QOS_NULL => return None,
            sys::ksnp_qos_type::KSNP_QOS_LIST => {
                // SAFETY: QOS_LIST means the list member is set.
                let list = unsafe { value.anon_1.list };
                // SAFETY: The values pointer is valid for the lifetime of the
                // list and layout compatible.
                Self::List(unsafe { slice::from_raw_parts(list.values.cast::<Rate>(), list.count) })
            }
            sys::ksnp_qos_type::KSNP_QOS_RANGE => {
                // SAFETY: QOS_RANGE means the range member is set.
                let range = unsafe { value.anon_1.range };
                Self::Range {
                    // ASSERT: QoS range values must be valid.
                    min: Rate::from_rate(range.min).unwrap(),
                    // ASSERT: QoS range values must be valid.
                    max: Rate::from_rate(range.max).unwrap(),
                }
            }
            // ASSERT: Only the enumerated QoS types are valid.
            _ => unreachable!(),
        };
        Some(this)
    }

    pub(crate) fn to_sys(&self) -> sys::ksnp_qos_rate {
        match self {
            Self::Empty => sys::ksnp_qos_rate {
                type_: sys::ksnp_qos_type::KSNP_QOS_NULL,
                anon_1: sys::ksnp_qos_rate__bindgen_ty_1 { none: 0 },
            },
            &Self::List(list) => sys::ksnp_qos_rate {
                type_: sys::ksnp_qos_type::KSNP_QOS_LIST,
                anon_1: sys::ksnp_qos_rate__bindgen_ty_1 {
                    list: sys::ksnp_qos_list_rate {
                        values: list.as_ptr().cast::<sys::ksnp_rate>(),
                        count: list.len(),
                    },
                },
            },
            &Self::Range { min, max } => sys::ksnp_qos_rate {
                type_: sys::ksnp_qos_type::KSNP_QOS_RANGE,
                anon_1: sys::ksnp_qos_rate__bindgen_ty_1 {
                    range: sys::ksnp_qos_range_rate {
                        min: min.into_sys(),
                        max: max.into_sys(),
                    },
                },
            },
        }
    }
}

#[derive(Debug)]
pub struct StreamQosParams<'evt> {
    pub chunk_size: Option<Qos<'evt, u16>>,
    pub min_bps: Option<Qos<'evt, Rate>>,
    pub ttl: Option<Qos<'evt, u32>>,
    pub provision_size: Option<Qos<'evt, u32>>,
    pub extensions: *mut sys::json_object,
}

impl<'evt> StreamQosParams<'evt> {
    pub fn from_qos_params(params: &'evt sys::ksnp_stream_qos_params) -> Self {
        Self {
            chunk_size: Qos::<u16>::from_qos(&params.chunk_size),
            min_bps: Qos::<Rate>::from_qos(&params.min_bps),
            ttl: Qos::<u32>::from_qos(&params.ttl),
            provision_size: Qos::<u32>::from_qos(&params.provision_size),
            extensions: params.extensions,
        }
    }

    pub(crate) unsafe fn to_sys(&self) -> sys::ksnp_stream_qos_params {
        sys::ksnp_stream_qos_params {
            chunk_size: self
                .chunk_size
                .as_ref()
                .map_or(Qos::<u16>::NONE, Qos::<u16>::to_sys),
            min_bps: self
                .min_bps
                .as_ref()
                .map_or(Qos::<Rate>::NONE, Qos::<Rate>::to_sys),
            ttl: self
                .ttl
                .as_ref()
                .map_or(Qos::<u32>::NONE, Qos::<u32>::to_sys),
            provision_size: self
                .provision_size
                .as_ref()
                .map_or(Qos::<u32>::NONE, Qos::<u32>::to_sys),
            extensions: self.extensions,
        }
    }
}

/// Direction in which a connection should be closed.
pub enum CloseDirection {
    /// Close the read direction.
    Read,
    /// Close the write direction.
    Write,
    /// Close both directions.
    Both,
}

impl From<CloseDirection> for sys::ksnp_close_direction {
    fn from(value: CloseDirection) -> Self {
        match value {
            CloseDirection::Read => Self::KSNP_CLOSE_READ,
            CloseDirection::Write => Self::KSNP_CLOSE_WRITE,
            CloseDirection::Both => Self::KSNP_CLOSE_BOTH,
        }
    }
}
