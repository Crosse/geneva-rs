use std::str::FromStr;

use crate::actions::{
    ActionTree, DropAction, DuplicateAction, FragmentAction, GenevaAction, SendAction, TamperAction,
};
use crate::errors::*;
use crate::triggers::{GenevaTrigger, IPField, IPTrigger, TCPField, TCPTrigger};
use crate::Strategy;

use pest::{iterators::Pairs, Parser};

#[derive(Parser)]
#[grammar = "parser/geneva.pest"]
struct GenevaParser;

pub fn parse_strategy(s: &str) -> Result<Strategy> {
    let mut parsed_strategy = GenevaParser::parse(Rule::strategy, s)?;

    let forests = parsed_strategy.next().unwrap();
    let mut strategy = Strategy::default();

    let mut forest = vec![];
    for f in forests.into_inner() {
        match f.as_rule() {
            Rule::forest => {
                for action_tree in f.into_inner() {
                    let at = parse_action_tree(&mut action_tree.into_inner())?;
                    forest.push(at);
                }
            }
            Rule::forest_separator => {
                strategy.outbound = if forest.is_empty() {
                    None
                } else {
                    Some(forest)
                };
                forest = vec![];
            }
            Rule::EOI => {
                strategy.inbound = if forest.is_empty() {
                    None
                } else {
                    Some(forest)
                };
                // unneeded, but rustc complains since it doesn't know this is a terminal match.
                forest = vec![];
            }
            _ => unreachable!(),
        }
    }

    Ok(strategy)
}

fn parse_action_tree(f: &mut Pairs<Rule>) -> Result<ActionTree> {
    let mut trigger = None;
    let mut action = None;

    for part in f {
        match part.as_rule() {
            Rule::trigger => {
                trigger = Some(parse_trigger(&mut part.into_inner())?);
            }
            Rule::action => {
                action = Some(parse_action(&mut part.into_inner())?);
            }
            _ => {
                unreachable!();
            }
        }
    }

    Ok(ActionTree {
        trigger: trigger.unwrap(),
        root_action: Box::new(action.unwrap()),
    })
}

fn parse_trigger(f: &mut Pairs<Rule>) -> Result<GenevaTrigger> {
    let proto = f.next().unwrap().as_str();
    let field = f.next().unwrap().as_str();
    let value = f.next().unwrap().as_str();
    match proto.to_lowercase().as_str() {
        "tcp" => {
            let field: TCPField = TCPField::from_str(field)?;
            Ok(GenevaTrigger::TCP(TCPTrigger::new(
                field,
                value.to_string(),
                0,
            )?))
        }
        "ip" => {
            let field: IPField = IPField::from_str(field)?;
            Ok(GenevaTrigger::IP(IPTrigger::new(
                field,
                value.to_string(),
                0,
                0,
            )?))
        }
        _ => unreachable!(),
    }
}

fn parse_action(f: &mut Pairs<Rule>) -> Result<GenevaAction> {
    let inner_rules = f.next().unwrap();
    match inner_rules.as_rule() {
        Rule::send => Ok(SendAction::default().into()),
        Rule::drop => Ok(DropAction::default().into()),
        Rule::duplicate => {
            let mut l_action = SendAction::default().into();
            let mut r_action = SendAction::default().into();
            let mut action = None;
            for a in inner_rules.into_inner() {
                match a.as_rule() {
                    Rule::action => {
                        action = Some(parse_action(&mut a.into_inner())?);
                    }
                    Rule::comma => {
                        if let Some(action) = action {
                            l_action = action;
                        }
                        action = None;
                    }
                    _ => unreachable!(),
                }
            }
            if let Some(action) = action {
                r_action = action;
            }
            Ok(DuplicateAction::new(l_action, r_action).into())
        }
        _ => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use crate::actions::GenevaAction;
    use crate::parse_strategy;
    use crate::triggers::{GenevaTrigger, Trigger};

    #[test]
    fn parse_empty_strategy() {
        let result = parse_strategy(r#"\/"#);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_simple_strategy() {
        let s = r#"[TCP:flags:SA]-drop-| \/"#;
        let result = parse_strategy(s);
        assert!(result.is_ok());

        let strategy = result.unwrap();

        assert_eq!(strategy.to_string(), s);

        assert!(strategy.inbound.is_none());
        assert!(strategy.outbound.is_some());

        let outbound = strategy.outbound.unwrap();
        assert_eq!(outbound.len(), 1);

        let trigger = &outbound[0].trigger;
        assert!(matches!(trigger, GenevaTrigger::TCP(_)));

        let trigger = match trigger {
            GenevaTrigger::TCP(t) => t,
            _ => unreachable!(),
        };

        assert_eq!(trigger.protocol(), "TCP");
        assert_eq!(trigger.field(), "flags");
        assert_eq!(trigger.value(), "SA");
        assert_eq!(trigger.gas(), 0);

        let action = &outbound[0].root_action;
        assert!(matches!(**action, GenevaAction::Drop(_)));
    }
}
