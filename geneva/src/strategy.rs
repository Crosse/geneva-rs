//! This module provides types and functions for creating Geneva strategies.
//!
//! A Geneva strategy consists of zero or more action trees that can be applied to inbound or
//! outbound packets. The actions trees encode what actions to take on a packet. A strategy,
//! conceptually, looks like this:
//!
//! ```text
//!   outbound-forest \/ inbound-forest
//! ```
//!
//! `outbound-forest` and `inbound-forest` are ordered lists of `(trigger, action tree)` pairs. The
//! Geneva paper calls these ordered lists "forests". The outbound and inbound forests are separated
//! by the `\/` characters (that is a backslash followed by a forward-slash); if the strategy omits
//! one or the other, then that side of the `\/` is left empty. For example, a strategy that only
//! includes an outbound forest would take the form `outbound \/`, whereas an inbound-only strategy
//! would be `\/ inbound`.
//!
//! The original Geneva paper does not have a name for these `(trigger, action tree)` pairs. In
//! practice, however, the Python code actually defines an action tree as a `(trigger, action)`
//! pair, where the "action" is the root of a tree of actions. This crate follows this nomenclature
//! as well.
//!
//! A real example, taken from the [original paper][geneva-paper] (pg 2202), would look like this:
//!
//! ```text
//!     [TCP:flags:S]-
//!        duplicate(
//!           tamper{TCP:flags:replace:SA}(
//!              send),
//!            send)-| \/
//!     [TCP:flags:R]-drop-|
//! ```
//!
//! In this example, the outbound forest would trigger on TCP packets that have just the `SYN` flag
//! set, and would perform a few different actions on those packets. The inbound forest would only
//! apply to TCP packets with the `RST` flag set, and would simply drop them. Each of the forests in
//! the example are made up of a single `(trigger, action tree)` pair.
//!
//! [geneva-paper]: https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf
use std::fmt;

use crate::actions::ActionTree;
use crate::errors::*;
use crate::Packet;

/// Represents the direction to which a [Forest]'s action trees applies.
pub enum Direction {
    /// The `Forest` applies to packets egressing the system.
    Inbound,
    /// The `Forest` applies to packet ingressing the system.
    Outbound,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
        .fmt(f)
    }
}

/// An ordered list of [ActionTree]s.
pub type Forest = Vec<ActionTree>;

/// Zero or more action trees that can be applied to inbound or outbound packets.
#[derive(Default, Debug)]
pub struct Strategy {
    pub outbound: Option<Forest>,
    pub inbound: Option<Forest>,
}

impl Strategy {
    /// Applies the strategy to the given packet, returning zero or more potentially-modified packets.
    pub fn apply(&self, pkt: Packet, direction: Direction) -> Result<Vec<Packet>> {
        let forest = match direction {
            Direction::Inbound => &self.inbound,
            Direction::Outbound => &self.outbound,
        };

        if forest.is_none() {
            return Ok(vec![pkt]);
        }

        let forest = forest.as_ref().unwrap();
        if forest.is_empty() {
            return Ok(vec![pkt]);
        }

        let mut packets = vec![];

        // For forests with more than one action tree, we clone the packet for all but the last
        // action tree. The last tree can take the original packet. This should avoid an extra copy.
        // For forests with only one action tree, this first loop should not fire.
        for action_tree in forest.iter().take(forest.len().saturating_sub(1)) {
            let pkt = pkt.clone();
            if action_tree.matches(&pkt) {
                let mut pkts = action_tree.apply(pkt)?;
                packets.append(&mut pkts);
            } else {
                packets.push(pkt);
            }
        }

        if let Some(action_tree) = forest.last() {
            if action_tree.matches(&pkt) {
                let mut pkts = action_tree.apply(pkt)?;
                packets.append(&mut pkts);
            } else {
                packets.push(pkt);
            }
        }

        Ok(packets)
    }
}
