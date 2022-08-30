//! Describes the actions that can be applied to a given packet.
//!
//! See the top-level documentation for more details.
use std::fmt;

use crate::errors::*;
use crate::Packet;

mod fragment;
pub use fragment::FragmentAction;

mod tamper;
pub use tamper::TamperAction;

/// Describes a Geneva action, or the steps to perform to manipulate a packet.
pub trait Action: fmt::Display {
    /// Runs this action on the given packet, producing zero or more potentially-modified packets.
    fn run(&self, pkt: Packet) -> Result<Vec<Packet>>;
}

/// Represents one of the Geneva actions.
#[derive(Debug, Clone)]
pub enum GenevaAction {
    /// The `send` action.
    Send(SendAction),

    /// The `drop` action.
    Drop(DropAction),

    /// The `duplicate` action.
    Duplicate(DuplicateAction),

    /// The `fragment` action.
    Fragment(FragmentAction),

    /// The `tamper` action.
    Tamper(TamperAction),
}

impl Action for GenevaAction {
    fn run(&self, pkt: Packet) -> Result<Vec<Packet>> {
        match self {
            Self::Send(a) => a.run(pkt),
            Self::Drop(a) => a.run(pkt),
            Self::Duplicate(a) => a.run(pkt),
            Self::Fragment(a) => a.run(pkt),
            Self::Tamper(a) => a.run(pkt),
        }
    }
}

impl fmt::Display for GenevaAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Send(a) => a.fmt(f),
            Self::Drop(a) => a.fmt(f),
            Self::Duplicate(a) => a.fmt(f),
            Self::Fragment(a) => a.fmt(f),
            Self::Tamper(a) => a.fmt(f),
        }
    }
}

/// An [Action] that passes the given packet on without modification.
#[derive(Default, Debug, Clone, Copy)]
pub struct SendAction {}

impl Action for SendAction {
    fn run(&self, pkt: Packet) -> Result<Vec<Packet>> {
        Ok(vec![pkt])
    }
}

impl fmt::Display for SendAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Canonically, the 'send' action can be elided, so let's do that for the default string representation.
        f.write_str("")
    }
}

impl From<SendAction> for GenevaAction {
    fn from(a: SendAction) -> Self {
        Self::Send(a)
    }
}

/// An [Action] that duplicates a packet and applies separate action trees to each.
///
/// The `duplicate(a1, a2)` action copies the original packet, then applies [Action] `a1` to the
/// original and `a2` to the copy. For example, if `a1` and `a2` are both "[send](SendAction)"
/// actions, then the action will yield two packets identical to the first.
#[derive(Debug, Clone)]
pub struct DuplicateAction {
    left: Box<GenevaAction>,
    right: Box<GenevaAction>,
}

impl DuplicateAction {
    pub fn new(left: GenevaAction, right: GenevaAction) -> Self {
        Self {
            left: Box::new(left),
            right: Box::new(right),
        }
    }
}

impl Action for DuplicateAction {
    fn run(&self, pkt: Packet) -> Result<Vec<Packet>> {
        let dupe = Packet::new(pkt.as_slice().to_vec());

        let mut result = vec![];

        let mut lpackets = self.left.run(pkt)?;
        result.append(&mut lpackets);

        let mut rpackets = self.right.run(dupe)?;
        result.append(&mut rpackets);

        Ok(result)
    }
}

impl fmt::Display for DuplicateAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let left = format!("{}", self.left);
        let right = format!("{}", self.right);
        let args = if left.len() + right.len() == 0 {
            "".to_string()
        } else {
            format!("({},{})", left, right)
        };
        write!(f, "duplicate{}", args)
    }
}

impl From<DuplicateAction> for GenevaAction {
    fn from(a: DuplicateAction) -> Self {
        Self::Duplicate(a)
    }
}

/// An [Action] that drops the given packet.
#[derive(Default, Debug, Clone, Copy)]
pub struct DropAction {}

impl Action for DropAction {
    fn run(&self, _: Packet) -> Result<Vec<Packet>> {
        Ok(vec![])
    }
}

impl fmt::Display for DropAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("drop")
    }
}

impl From<DropAction> for GenevaAction {
    fn from(a: DropAction) -> Self {
        Self::Drop(a)
    }
}

/// Represents a Geneva (trigger, action) pair.
///
/// Technically, Geneva uses the term "action tree" to refer to the tree of actions in the tuple
/// (trigger, action tree). In other words, `root_action` here is what they call the "action
/// tree". They have no name for the (trigger, action tree) tuple, which this type actually
/// represents.
pub struct ActionTree {
    /// The [Trigger] that, if matched, will fire this action tree.
    pub trigger: GenevaTrigger,

    /// The root [Action] of the tree. It may have subordinate actions that it calls.
    pub root_action: Box<GenevaAction>,
}

impl ActionTree {
    /// Returns `true` if this action tree's trigger matches the given [Packet].
    pub fn matches(&self, pkt: &Packet) -> bool {
        self.trigger.matches(pkt)
    }

    /// Applies this action tree to the [Packet], returning zero or more potentially-modified packets.
    pub fn apply(&self, pkt: Packet) -> Result<Vec<Packet>> {
        self.root_action.run(pkt)
    }
}

impl fmt::Display for ActionTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}-|", self.trigger, self.root_action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_str() {
        let a = SendAction::default();
        assert_eq!(a.to_string(), "");
    }

    #[test]
    fn drop_str() {
        let a = DropAction::default();
        assert_eq!(a.to_string(), "drop");
    }

    #[test]
    fn duplicate_str() {
        let mut a =
            DuplicateAction::new(SendAction::default().into(), SendAction::default().into());
        assert_eq!(a.to_string(), "duplicate");

        a.left = Box::new(DropAction::default().into());
        assert_eq!(a.to_string(), "duplicate(drop,)");

        a.right = Box::new(DropAction::default().into());
        assert_eq!(a.to_string(), "duplicate(drop,drop)");

        a.left = Box::new(SendAction::default().into());
        assert_eq!(a.to_string(), "duplicate(,drop)");
    }

    #[test]
    fn duplicate_str_multiple_levels() {
        let inner1 =
            DuplicateAction::new(SendAction::default().into(), DropAction::default().into());
        let inner = DuplicateAction::new(SendAction::default().into(), inner1.into());
        let a = DuplicateAction::new(inner.into(), DropAction::default().into());
        assert_eq!(
            a.to_string(),
            "duplicate(duplicate(,duplicate(,drop)),drop)"
        );
    }

    #[test]
    fn send_result() {
        let a = SendAction::default();
        let pkt = Packet::new(vec![0, 1, 2, 3, 4]);

        let result = a.run(pkt.clone());
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], pkt);
    }

    #[test]
    fn drop_result() {
        let a = DropAction::default();
        let pkt = Packet::new(vec![0, 1, 2, 3, 4]);

        let result = a.run(pkt);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn duplicate_send_result() {
        let a = DuplicateAction::new(SendAction::default().into(), SendAction::default().into());
        let pkt = Packet::new(vec![0, 1, 2, 3, 4]);

        let result = a.run(pkt.clone());
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.len(), 2);

        assert_eq!(result, vec![pkt.clone(), pkt]);
    }
}
