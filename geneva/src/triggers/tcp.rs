use std::fmt;
use std::str::FromStr;

use crate::errors::*;
use crate::triggers::Trigger;
use crate::Packet;

/// Supported fields in the TCP header that can be used for triggers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TCPField {
    SourcePort,
    DestPort,
    Seq,
    Ack,
    DataOffset,
    Reserved,
    Flags,
    Window,
    Checksum,
    UrgentPointer,
    Payload,
    OptionEOL,
    OptionNOP,
    OptionMSS,
    OptionWScale,
    OptionSackOk,
    OptionSack,
    OptionTimestamp,
    OptionAltChecksum,
    OptionAltChecksumOpt,
    OptionMD5Header,
    OptionUTO,
}

impl fmt::Display for TCPField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TCPField::*;
        match self {
            SourcePort => "sport",
            DestPort => "dport",
            Seq => "seq",
            Ack => "ack",
            DataOffset => "dataofs",
            Reserved => "reserved",
            Flags => "flags",
            Window => "window",
            Checksum => "chksum",
            UrgentPointer => "urgptr",
            Payload => "load",
            OptionEOL => "options-eol",
            OptionNOP => "options-nop",
            OptionMSS => "options-mss",
            OptionWScale => "options-wscale",
            OptionSackOk => "options-sackok",
            OptionSack => "options-sack",
            OptionTimestamp => "options-timestamp",
            OptionAltChecksum => "options-altchksum",
            OptionAltChecksumOpt => "options-altchksumopt",
            OptionMD5Header => "options-md5header",
            OptionUTO => "options-uto",
        }
        .fmt(f)
    }
}

impl FromStr for TCPField {
    type Err = Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        use TCPField::*;
        match s {
            "sport" => Ok(SourcePort),
            "dport" => Ok(DestPort),
            "seq" => Ok(Seq),
            "ack" => Ok(Ack),
            "dataofs" => Ok(DataOffset),
            "reserved" => Ok(Reserved),
            "flags" => Ok(Flags),
            "window" => Ok(Window),
            "chksum" => Ok(Checksum),
            "urgptr" => Ok(UrgentPointer),
            "load" => Ok(Payload),
            "options-eol" => Ok(OptionEOL),
            "options-nop" => Ok(OptionNOP),
            "options-mss" => Ok(OptionMSS),
            "options-wscale" => Ok(OptionWScale),
            "options-sackok" => Ok(OptionSackOk),
            "options-sack" => Ok(OptionSack),
            "options-timestamp" => Ok(OptionTimestamp),
            "options-altchksum" => Ok(OptionAltChecksum),
            "options-altchksumopt" => Ok(OptionAltChecksumOpt),
            "options-md5header" => Ok(OptionMD5Header),
            "options-uto" => Ok(OptionUTO),
            _ => Err(Error::Parse(s.to_string())),
        }
    }
}

/// A [Trigger] that matches on the TCP layer.
#[derive(Debug, Clone)]
pub struct TCPTrigger {
    field: TCPField,
    value: String,
    gas: usize,
}

impl TCPTrigger {
    /// Creates a new `TCPTrigger`.
    pub fn new(field: TCPField, value: String, gas: usize) -> Result<Self> {
        // TODO: validate fields
        Ok(Self { field, value, gas })
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

impl Trigger for TCPTrigger {
    fn protocol(&self) -> String {
        "TCP".to_string()
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

impl fmt::Display for TCPTrigger {
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
