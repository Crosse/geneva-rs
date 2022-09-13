use std::fmt;
use std::str::FromStr;

use crate::errors::*;
use crate::triggers::Trigger;
use crate::Packet;

/// Supported fields in the IP header that can be used for triggers.
#[derive(Debug, Clone)]
pub enum IPField {
    Version,
    IHL,
    TOS,
    Length,
    Identification,
    Flags,
    FragmentOffset,
    TTL,
    Protocol,
    Checksum,
    SourceAddress,
    DestAddress,
    Payload,
}

impl fmt::Display for IPField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use IPField::*;
        match self {
            Version => "version",
            IHL => "ihl",
            TOS => "tos",
            Length => "len",
            Identification => "id",
            Flags => "flags",
            FragmentOffset => "frag",
            TTL => "ttl",
            Protocol => "protocol",
            Checksum => "chksum",
            SourceAddress => "src",
            DestAddress => "dst",
            Payload => "load",
        }
        .fmt(f)
    }
}

impl FromStr for IPField {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use IPField::*;
        match s {
            "version" => Ok(Version),
            "ihl" => Ok(IHL),
            "TOS" => Ok(TOS),
            "len" => Ok(Length),
            "id" => Ok(Identification),
            "flags" => Ok(Flags),
            "frag" => Ok(FragmentOffset),
            "ttl" => Ok(TTL),
            "protocol" => Ok(Protocol),
            "chksum" => Ok(Checksum),
            "src" => Ok(SourceAddress),
            "dst" => Ok(DestAddress),
            "load" => Ok(Payload),
            _ => Err(Error::Parse(s.to_string())),
        }
    }
}

/// A [Trigger] that matches on the IP layer.
#[derive(Debug, Clone)]
pub struct IPTrigger {
    field: IPField,
    value: String,
    gas: usize,
    _ip_field: u8,
}

impl IPTrigger {
    /// Creates a new `IPTrigger`.
    pub fn new(field: IPField, value: String, gas: usize, _ip_field: u8) -> Self {
        Self {
            field,
            value,
            gas,
            _ip_field,
        }
    }
}

impl Trigger for IPTrigger {
    fn protocol(&self) -> String {
        "IP".to_string()
    }

    fn field(&self) -> String {
        self.field.to_string()
    }

    fn gas(&self) -> usize {
        self.gas
    }

    fn matches(&self, _pkt: &Packet) -> bool {
        unimplemented!()
    }
}

impl fmt::Display for IPTrigger {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let gas = if self.gas > 0 {
            format!(":{}", self.gas)
        } else {
            "".to_string()
        };
        write!(
            f,
            "[{}:{}:{}{}]",
            self.protocol(),
            self.field,
            self.value,
            gas
        )
    }
}
