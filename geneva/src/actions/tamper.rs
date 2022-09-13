use std::fmt;

use crate::errors::*;
use crate::Packet;

use super::{Action, GenevaAction};

/// Describes the way that the `tamper` action can manipulate a packet.
#[derive(Debug, Clone)]
pub enum TamperMode {
    /// Replaces the value of a packet field with the given value.
    Replace,

    /// Replaces the value of a packet field with a randomly-generated value.
    Corrupt,

    /// Adds the value to a packet field.
    Add,
}

impl fmt::Display for TamperMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replace => f.write_str("replace"),
            Self::Corrupt => f.write_str("corrupt"),
            Self::Add => f.write_str("add"),
        }
    }
}

/// An [Action] that modifies packets (typically values in the packet header).
#[derive(Debug, Clone)]
pub struct TamperAction {
    protocol: String,
    field: String,
    new_value: String,
    mode: TamperMode,
    action: Box<GenevaAction>,
}

impl TamperAction {
    /// Creates a new `TamperAction`.
    pub fn new(
        protocol: String,
        field: String,
        new_value: String,
        mode: TamperMode,
        action: GenevaAction,
    ) -> Result<Self> {
        Ok(Self {
            protocol,
            field,
            new_value,
            mode,
            action: Box::new(action),
        })
    }
}

impl Action for TamperAction {
    fn run(&self, _pkt: Packet) -> Result<Vec<Packet>> {
        unimplemented!()
    }
}

impl fmt::Display for TamperAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let new_value = if let TamperMode::Replace = self.mode {
            format!(":{}", self.new_value)
        } else {
            "".to_string()
        };

        write!(
            f,
            "tamper{{{}:{}:{}{}}}({},)",
            self.protocol, self.field, self.mode, new_value, self.action
        )
    }
}
