//! Describes the actions that can be applied to a given packet.
//!
//! See the top-level documentation for more details.
use std::fmt;

use crate::errors::*;
use crate::Packet;

mod fragment;
pub use fragment::Fragment;

#[derive(Debug, Clone)]
pub enum GenevaAction {
    Send(Send),
    Drop(Drop),
    Duplicate(Duplicate),
    Fragment(Fragment),
}

impl Action for GenevaAction {
    fn run(&self, pkt: Packet) -> Result<Vec<Packet>> {
        match self {
            Self::Send(a) => a.run(pkt),
            Self::Drop(a) => a.run(pkt),
            Self::Duplicate(a) => a.run(pkt),
            Self::Fragment(a) => a.run(pkt),
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
        }
    }
}

// Describes a Geneva action.
pub trait Action: fmt::Display {
    fn run(&self, pkt: Packet) -> Result<Vec<Packet>>;
}

/// A Geneva action that passes the given packet on without modification.
#[derive(Default, Debug, Clone, Copy)]
pub struct Send {}

impl Action for Send {
    fn run(&self, pkt: Packet) -> Result<Vec<Packet>> {
        Ok(vec![pkt])
    }
}

impl fmt::Display for Send {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Canonically, the 'send' action can be elided, so let's do that for the default string representation.
        f.write_str("")
    }
}

impl From<Send> for GenevaAction {
    fn from(a: Send) -> Self {
        Self::Send(a)
    }
}

/// A Geneva action that duplicates a packet and applies separate action trees to each.
#[derive(Debug, Clone)]
pub struct Duplicate {
    left: Box<GenevaAction>,
    right: Box<GenevaAction>,
}

impl Duplicate {
    pub fn new(left: GenevaAction, right: GenevaAction) -> Self {
        Self {
            left: Box::new(left),
            right: Box::new(right),
        }
    }
}

impl Action for Duplicate {
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

impl fmt::Display for Duplicate {
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

impl From<Duplicate> for GenevaAction {
    fn from(a: Duplicate) -> Self {
        Self::Duplicate(a)
    }
}

/// A Geneva action that drops the given packet.
#[derive(Default, Debug, Clone, Copy)]
pub struct Drop {}

impl Action for Drop {
    fn run(&self, _: Packet) -> Result<Vec<Packet>> {
        Ok(vec![])
    }
}

impl fmt::Display for Drop {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("drop")
    }
}

impl From<Drop> for GenevaAction {
    fn from(a: Drop) -> Self {
        Self::Drop(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn send_str() {
        let a = Send::default();
        assert_eq!(a.to_string(), "");
    }

    #[test]
    fn drop_str() {
        let a = Drop::default();
        assert_eq!(a.to_string(), "drop");
    }

    #[test]
    fn duplicate_str() {
        let mut a = Duplicate::new(Send::default().into(), Send::default().into());
        assert_eq!(a.to_string(), "duplicate");

        a.left = Box::new(Drop::default().into());
        assert_eq!(a.to_string(), "duplicate(drop,)");

        a.right = Box::new(Drop::default().into());
        assert_eq!(a.to_string(), "duplicate(drop,drop)");

        a.left = Box::new(Send::default().into());
        assert_eq!(a.to_string(), "duplicate(,drop)");
    }

    #[test]
    fn duplicate_str_multiple_levels() {
        let inner1 = Duplicate::new(Send::default().into(), Drop::default().into());
        let inner = Duplicate::new(Send::default().into(), inner1.into());
        let a = Duplicate::new(inner.into(), Drop::default().into());
        assert_eq!(
            a.to_string(),
            "duplicate(duplicate(,duplicate(,drop)),drop)"
        );
    }

    #[test]
    fn send_result() {
        let a = Send::default();
        let pkt = Packet::new(vec![0, 1, 2, 3, 4]);

        let result = a.run(pkt.clone());
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], pkt);
    }

    #[test]
    fn drop_result() {
        let a = Drop::default();
        let pkt = Packet::new(vec![0, 1, 2, 3, 4]);

        let result = a.run(pkt);
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn duplicate_send_result() {
        let a = Duplicate::new(Send::default().into(), Send::default().into());
        let pkt = Packet::new(vec![0, 1, 2, 3, 4]);

        let result = a.run(pkt.clone());
        assert!(result.is_ok());

        let result = result.unwrap();
        assert_eq!(result.len(), 2);

        assert_eq!(result, vec![pkt.clone(), pkt]);
    }
}
