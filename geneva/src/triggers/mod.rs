use std::fmt;

use crate::Packet;

mod ip;
pub use ip::*;

mod tcp;
pub use tcp::*;

/// Describes a Geneva trigger, which is responsible for deciding which packets an
/// [Action](crate::actions::Action) should apply to.
pub trait Trigger: fmt::Display {
    /// The protocol layer against which a trigger matches.
    fn protocol(&self) -> String;

    /// The (protocol-specific) field to match.
    fn field(&self) -> String;

    /// How many times a trigger can fire before it stops triggering.
    fn gas(&self) -> usize;

    /// Returns `true` if the packet matches this trigger, or `false` otherwise.
    fn matches(&self, pkt: &Packet) -> bool;
}

/// Represents one of the Geneva triggers.
#[derive(Debug, Clone)]
pub enum GenevaTrigger {
    /// A trigger that applies to a packet's IP layer.
    IP(IPTrigger),

    /// A trigger that applies to a packet's TCP layer.
    TCP(TCPTrigger),
}

impl Trigger for GenevaTrigger {
    fn protocol(&self) -> String {
        match self {
            GenevaTrigger::IP(t) => t.protocol(),
            GenevaTrigger::TCP(t) => t.protocol(),
        }
    }

    fn field(&self) -> String {
        match self {
            GenevaTrigger::IP(t) => t.field(),
            GenevaTrigger::TCP(t) => t.field(),
        }
    }

    fn gas(&self) -> usize {
        match self {
            GenevaTrigger::IP(t) => t.gas(),
            GenevaTrigger::TCP(t) => t.gas(),
        }
    }

    fn matches(&self, pkt: &Packet) -> bool {
        match self {
            GenevaTrigger::IP(t) => t.matches(pkt),
            GenevaTrigger::TCP(t) => t.matches(pkt),
        }
    }
}

impl fmt::Display for GenevaTrigger {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IP(t) => t.fmt(f),
            Self::TCP(t) => t.fmt(f),
        }
    }
}
