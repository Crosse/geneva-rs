use std::fmt;

use crate::errors::*;
use crate::Packet;

use super::{Action, GenevaAction};

#[derive(Debug, Clone)]
pub struct Fragment {
    protocol: u16,
    fragment_size: u16,
    in_order: bool,
    _overlap: u16,
    left_action: Box<GenevaAction>,
    right_action: Box<GenevaAction>,
}

impl Fragment {
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

impl Action for Fragment {
    fn run(&self, _pkt: Packet) -> Result<Vec<Packet>> {
        unimplemented!()
    }
}

impl fmt::Display for Fragment {
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
    use crate::actions::{Drop, Send};

    #[test]
    fn fragment_str() {
        let a = Fragment::new(
            6,
            12,
            true,
            0,
            Send::default().into(),
            Send::default().into(),
        );
        assert!(a.is_ok());

        let mut a = a.unwrap();
        assert_eq!(a.to_string(), "fragment{6:12:True}");

        a.in_order = false;
        assert_eq!(a.to_string(), "fragment{6:12:False}");

        a.left_action = Box::new(Drop::default().into());
        assert_eq!(a.to_string(), "fragment{6:12:False}(drop,)");

        a.right_action = Box::new(Drop::default().into());
        assert_eq!(a.to_string(), "fragment{6:12:False}(drop,drop)");

        a.left_action = Box::new(Send::default().into());
        assert_eq!(a.to_string(), "fragment{6:12:False}(,drop)");
    }
}
