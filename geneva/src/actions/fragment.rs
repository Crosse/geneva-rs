use std::fmt;

use crate::errors::*;
use crate::Packet;

use super::{Action, GenevaAction};

/// An [Action] that takes the original packet and fragments it, then applies separate `Action`s to
/// each fragment.
///
/// The syntax of a fragment rule is: `fragment{protocol:offset:inOrder}(a1, a2)`.
///
/// Since both the IP and TCP layers support fragmentation, the rule must specify which layer's
/// payload to fragment. The first fragment will include up to _offset_ bytes of the layer's
/// payload; the second fragment will contain the rest. As an example, given an IPv4 packet with a
/// 60-byte payload and an 8-byte offset, the first fragment will have the same IP header as the
/// original packet (aside from the fields that must be fixed) and then the first eight bytes of the
/// payload. The second fragment will contain the other 52 bytes. (You can also indicate that the
/// fragments be returned out-of-order; i.e., reversed, by specifying "False" for the _inOrder_
/// argument in the syntax above.)
#[derive(Debug, Clone)]
pub struct FragmentAction {
    protocol: u16,
    fragment_size: u16,
    in_order: bool,
    _overlap: u16,
    left_action: Box<GenevaAction>,
    right_action: Box<GenevaAction>,
}

impl FragmentAction {
    /// Creates a new [FragmentAction].
    pub fn new(
        protocol: u16,
        fragment_size: u16,
        in_order: bool,
        _overlap: u16,
        left_action: GenevaAction,
        right_action: GenevaAction,
    ) -> Result<Self> {
        // XXX: need to check values for correctness
        Ok(Self {
            protocol,
            fragment_size,
            in_order,
            _overlap,
            left_action: Box::new(left_action),
            right_action: Box::new(right_action),
        })
    }
}

impl Action for FragmentAction {
    fn run(&self, _pkt: Packet) -> Result<Vec<Packet>> {
        unimplemented!()
    }
}

impl fmt::Display for FragmentAction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let left = format!("{}", self.left_action);
        let right = format!("{}", self.right_action);
        let args = if left.len() + right.len() == 0 {
            "".to_string()
        } else {
            format!("({},{})", left, right)
        };

        let in_order = if self.in_order { "True" } else { "False" };

        write!(
            f,
            "fragment{{{}:{}:{}}}{}",
            self.protocol, self.fragment_size, in_order, args
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::{DropAction, SendAction};

    #[test]
    fn fragment_str() {
        let a = FragmentAction::new(
            6,
            12,
            true,
            0,
            SendAction::default().into(),
            SendAction::default().into(),
        );
        assert!(a.is_ok());

        let mut a = a.unwrap();
        assert_eq!(a.to_string(), "fragment{6:12:True}");

        a.in_order = false;
        assert_eq!(a.to_string(), "fragment{6:12:False}");

        a.left_action = Box::new(DropAction::default().into());
        assert_eq!(a.to_string(), "fragment{6:12:False}(drop,)");

        a.right_action = Box::new(DropAction::default().into());
        assert_eq!(a.to_string(), "fragment{6:12:False}(drop,drop)");

        a.left_action = Box::new(SendAction::default().into());
        assert_eq!(a.to_string(), "fragment{6:12:False}(,drop)");
    }
}
