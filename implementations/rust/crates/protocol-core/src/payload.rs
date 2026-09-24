//! Bounded, allocation-free application payload codec and predicate evaluator.

use core::cmp::Ordering;

use crate::{
    AgentId, AttributeId, Error, MAX_ATTRIBUTE_BYTES, MAX_ATTRIBUTES, MAX_CLAUSES, MAX_VALUE_BYTES,
    Operator, TypeId,
};

const OP_ENVIRONMENT: u8 = 1;
const OP_SUBSCRIBE_PERMANENT: u8 = 2;
const OP_PUBLISH: u8 = 3;
const OP_RESPONSE: u8 = 4;
const OP_SUBSCRIBE: u8 = 5;

/// Borrowed typed value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueRef<'a> {
    /// Boolean value.
    Bool(bool),
    /// Signed 64-bit integer.
    I64(i64),
    /// Bounded byte string.
    Bytes(&'a [u8]),
}

/// One borrowed environment entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AttributeRef<'a> {
    /// Attribute identifier.
    pub id: AttributeId,
    /// Typed value.
    pub value: ValueRef<'a>,
}

/// One clause in a conjunction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClauseRef<'a> {
    /// Environment attribute to inspect.
    pub attribute: AttributeId,
    /// Comparison operation.
    pub operator: Operator,
    /// Typed right-hand operand.
    pub value: ValueRef<'a>,
}

/// Validated, borrowed environment.
#[derive(Clone, Copy, Debug)]
pub struct EnvironmentRef<'a> {
    bytes: &'a [u8],
    count: u8,
}

impl<'a> EnvironmentRef<'a> {
    /// Number of entries.
    pub const fn len(self) -> usize {
        self.count as usize
    }

    /// Whether no entries are present.
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Returns the first matching attribute. Duplicate IDs are rejected by the parser.
    pub fn get(self, wanted: AttributeId) -> Option<ValueRef<'a>> {
        let mut cursor = Cursor::new(self.bytes);
        for _ in 0..self.count {
            let id = AttributeId(cursor.u16().ok()?);
            let value = cursor.value(MAX_ATTRIBUTE_BYTES).ok()?;
            if id == wanted {
                return Some(value);
            }
        }
        None
    }

    /// Iterates over every validated attribute without allocating.
    pub const fn iter(self) -> EnvironmentIter<'a> {
        EnvironmentIter {
            cursor: Cursor::new(self.bytes),
            remaining: self.count,
        }
    }
}

/// Iterator over a validated environment.
pub struct EnvironmentIter<'a> {
    cursor: Cursor<'a>,
    remaining: u8,
}

impl<'a> Iterator for EnvironmentIter<'a> {
    type Item = AttributeRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let id = AttributeId(self.cursor.u16().ok()?);
        let value = self.cursor.value(MAX_ATTRIBUTE_BYTES).ok()?;
        self.remaining -= 1;
        Some(AttributeRef { id, value })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = usize::from(self.remaining);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for EnvironmentIter<'_> {}

/// Validated, borrowed conjunction.
#[derive(Clone, Copy, Debug)]
pub struct PredicateRef<'a> {
    bytes: &'a [u8],
    count: u8,
}

impl<'a> PredicateRef<'a> {
    /// Number of clauses.
    pub const fn len(self) -> usize {
        self.count as usize
    }

    /// An empty conjunction is true.
    pub const fn is_empty(self) -> bool {
        self.count == 0
    }

    /// Deterministically evaluates every clause against an environment.
    pub fn evaluate(self, environment: EnvironmentRef<'_>) -> bool {
        let mut cursor = Cursor::new(self.bytes);
        for _ in 0..self.count {
            let attribute = match cursor.u16() {
                Ok(value) => AttributeId(value),
                Err(_) => return false,
            };
            let operator = match cursor.u8().ok().and_then(Operator::from_u8) {
                Some(value) => value,
                None => return false,
            };
            let rhs = match cursor.value(MAX_ATTRIBUTE_BYTES) {
                Ok(value) => value,
                Err(_) => return false,
            };
            let Some(lhs) = environment.get(attribute) else {
                return false;
            };
            if !compare(lhs, operator, rhs) {
                return false;
            }
        }
        true
    }
}

/// Fully validated borrowed application operation.
#[derive(Clone, Copy, Debug)]
pub enum OperationRef<'a> {
    /// Environment replacement.
    SetEnvironment(EnvironmentRef<'a>),
    /// Subscription registration.
    Subscribe {
        /// Publication type.
        type_id: TypeId,
        /// Bounded subscription predicate.
        predicate: PredicateRef<'a>,
    },
    /// Permanent subscription registration.
    SubscribePermanent {
        /// Publication type.
        type_id: TypeId,
        /// Bounded subscription predicate.
        predicate: PredicateRef<'a>,
    },
    /// Publication request.
    Publish {
        /// Publication type.
        type_id: TypeId,
        /// Predicate evaluated against each subscriber environment.
        predicate: PredicateRef<'a>,
        /// Opaque bounded value.
        value: &'a [u8],
    },
    /// CA delivery.
    PublicationResponse {
        /// Publication type.
        type_id: TypeId,
        /// Authenticated publisher identity.
        publisher: AgentId,
        /// Opaque value.
        value: &'a [u8],
    },
}

/// Encodes a complete environment operation.
pub fn encode_environment(
    output: &mut [u8],
    attributes: &[AttributeRef<'_>],
) -> Result<usize, Error> {
    if attributes.len() > MAX_ATTRIBUTES {
        return Err(Error::Oversized);
    }
    ensure_unique_attributes(attributes)?;
    let mut writer = Writer::new(output);
    writer.u8(OP_ENVIRONMENT)?;
    writer.u8(u8::try_from(attributes.len()).map_err(|_| Error::Oversized)?)?;
    for attribute in attributes {
        writer.u16(attribute.id.0)?;
        writer.value(attribute.value, MAX_ATTRIBUTE_BYTES)?;
    }
    Ok(writer.position())
}

/// Encodes a subscription operation.
pub fn encode_subscribe(
    output: &mut [u8],
    type_id: TypeId,
    clauses: &[ClauseRef<'_>],
) -> Result<usize, Error> {
    let mut writer = Writer::new(output);
    writer.u8(OP_SUBSCRIBE)?;
    writer.u32(type_id.0)?;
    writer.predicate(clauses)?;
    Ok(writer.position())
}

/// Encodes a permanent subscription operation.
pub fn encode_subscribe_permanent(
    output: &mut [u8],
    type_id: TypeId,
    clauses: &[ClauseRef<'_>],
) -> Result<usize, Error> {
    let mut writer = Writer::new(output);
    writer.u8(OP_SUBSCRIBE_PERMANENT)?;
    writer.u32(type_id.0)?;
    writer.predicate(clauses)?;
    Ok(writer.position())
}

/// Encodes a publication operation.
pub fn encode_publish(
    output: &mut [u8],
    type_id: TypeId,
    clauses: &[ClauseRef<'_>],
    value: &[u8],
) -> Result<usize, Error> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(Error::Oversized);
    }
    let mut writer = Writer::new(output);
    writer.u8(OP_PUBLISH)?;
    writer.u32(type_id.0)?;
    writer.predicate(clauses)?;
    writer.bytes_u16(value, MAX_VALUE_BYTES)?;
    Ok(writer.position())
}

/// Encodes one CA publication delivery.
pub fn encode_response(
    output: &mut [u8],
    type_id: TypeId,
    publisher: AgentId,
    value: &[u8],
) -> Result<usize, Error> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(Error::Oversized);
    }
    let mut writer = Writer::new(output);
    writer.u8(OP_RESPONSE)?;
    writer.u32(type_id.0)?;
    writer.raw(&publisher.0)?;
    writer.bytes_u16(value, MAX_VALUE_BYTES)?;
    Ok(writer.position())
}

/// Parses exactly one operation and rejects trailing bytes and duplicate attributes.
pub fn parse_operation(input: &[u8]) -> Result<OperationRef<'_>, Error> {
    let mut cursor = Cursor::new(input);
    let operation = match cursor.u8()? {
        OP_ENVIRONMENT => {
            let count = cursor.u8()?;
            if count as usize > MAX_ATTRIBUTES {
                return Err(Error::Oversized);
            }
            let start = cursor.position;
            let mut ids = [0u16; MAX_ATTRIBUTES];
            for index in 0..count as usize {
                let id = cursor.u16()?;
                if ids[..index].contains(&id) {
                    return Err(Error::Malformed);
                }
                ids[index] = id;
                let _ = cursor.value(MAX_ATTRIBUTE_BYTES)?;
            }
            let end = cursor.position;
            OperationRef::SetEnvironment(EnvironmentRef {
                bytes: &input[start..end],
                count,
            })
        }
        OP_SUBSCRIBE => {
            let type_id = TypeId(cursor.u32()?);
            let predicate = cursor.predicate(input)?;
            OperationRef::Subscribe { type_id, predicate }
        }
        OP_SUBSCRIBE_PERMANENT => {
            let type_id = TypeId(cursor.u32()?);
            let predicate = cursor.predicate(input)?;
            OperationRef::SubscribePermanent { type_id, predicate }
        }
        OP_PUBLISH => {
            let type_id = TypeId(cursor.u32()?);
            let predicate = cursor.predicate(input)?;
            let value = cursor.bytes_u16(MAX_VALUE_BYTES)?;
            OperationRef::Publish {
                type_id,
                predicate,
                value,
            }
        }
        OP_RESPONSE => {
            let type_id = TypeId(cursor.u32()?);
            let publisher = AgentId(cursor.array()?);
            let value = cursor.bytes_u16(MAX_VALUE_BYTES)?;
            OperationRef::PublicationResponse {
                type_id,
                publisher,
                value,
            }
        }
        _ => return Err(Error::Malformed),
    };
    if cursor.position != input.len() {
        return Err(Error::Malformed);
    }
    Ok(operation)
}

fn compare(lhs: ValueRef<'_>, operator: Operator, rhs: ValueRef<'_>) -> bool {
    let ordering = match (lhs, rhs) {
        (ValueRef::Bool(a), ValueRef::Bool(b)) => Some(a.cmp(&b)),
        (ValueRef::I64(a), ValueRef::I64(b)) => Some(a.cmp(&b)),
        (ValueRef::Bytes(a), ValueRef::Bytes(b)) => Some(a.cmp(b)),
        _ => None,
    };
    let Some(ordering) = ordering else {
        return false;
    };
    match operator {
        Operator::Eq => ordering == Ordering::Equal,
        Operator::Ne => ordering != Ordering::Equal,
        Operator::Lt => ordering == Ordering::Less,
        Operator::Le => matches!(ordering, Ordering::Less | Ordering::Equal),
        Operator::Gt => ordering == Ordering::Greater,
        Operator::Ge => matches!(ordering, Ordering::Greater | Ordering::Equal),
    }
}

fn ensure_unique_attributes(attributes: &[AttributeRef<'_>]) -> Result<(), Error> {
    for (index, attribute) in attributes.iter().enumerate() {
        if attributes[..index]
            .iter()
            .any(|prior| prior.id == attribute.id)
        {
            return Err(Error::Malformed);
        }
    }
    Ok(())
}

struct Cursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = self.position.checked_add(length).ok_or(Error::Malformed)?;
        let bytes = self.input.get(self.position..end).ok_or(Error::Malformed)?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        self.take(1)?.first().copied().ok_or(Error::Malformed)
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?.try_into().map_err(|_| Error::Malformed)
    }

    fn bytes_u16(&mut self, maximum: usize) -> Result<&'a [u8], Error> {
        let length = self.u16()? as usize;
        if length > maximum {
            return Err(Error::Oversized);
        }
        self.take(length)
    }

    fn value(&mut self, maximum_bytes: usize) -> Result<ValueRef<'a>, Error> {
        match self.u8()? {
            1 => match self.u8()? {
                0 => Ok(ValueRef::Bool(false)),
                1 => Ok(ValueRef::Bool(true)),
                _ => Err(Error::Malformed),
            },
            2 => Ok(ValueRef::I64(i64::from_be_bytes(self.array()?))),
            3 => Ok(ValueRef::Bytes(self.bytes_u16(maximum_bytes)?)),
            _ => Err(Error::Malformed),
        }
    }

    fn predicate(&mut self, complete: &'a [u8]) -> Result<PredicateRef<'a>, Error> {
        let count = self.u8()?;
        if count as usize > MAX_CLAUSES {
            return Err(Error::Oversized);
        }
        let start = self.position;
        for _ in 0..count {
            let _ = self.u16()?;
            Operator::from_u8(self.u8()?).ok_or(Error::Malformed)?;
            let _ = self.value(MAX_ATTRIBUTE_BYTES)?;
        }
        let end = self.position;
        Ok(PredicateRef {
            bytes: &complete[start..end],
            count,
        })
    }
}

struct Writer<'a> {
    output: &'a mut [u8],
    position: usize,
}

impl<'a> Writer<'a> {
    fn new(output: &'a mut [u8]) -> Self {
        Self {
            output,
            position: 0,
        }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn raw(&mut self, value: &[u8]) -> Result<(), Error> {
        let end = self
            .position
            .checked_add(value.len())
            .ok_or(Error::Oversized)?;
        let destination = self
            .output
            .get_mut(self.position..end)
            .ok_or(Error::Oversized)?;
        destination.copy_from_slice(value);
        self.position = end;
        Ok(())
    }

    fn u8(&mut self, value: u8) -> Result<(), Error> {
        self.raw(&[value])
    }

    fn u16(&mut self, value: u16) -> Result<(), Error> {
        self.raw(&value.to_be_bytes())
    }

    fn u32(&mut self, value: u32) -> Result<(), Error> {
        self.raw(&value.to_be_bytes())
    }

    fn bytes_u16(&mut self, value: &[u8], maximum: usize) -> Result<(), Error> {
        if value.len() > maximum {
            return Err(Error::Oversized);
        }
        self.u16(u16::try_from(value.len()).map_err(|_| Error::Oversized)?)?;
        self.raw(value)
    }

    fn value(&mut self, value: ValueRef<'_>, maximum_bytes: usize) -> Result<(), Error> {
        match value {
            ValueRef::Bool(value) => {
                self.u8(1)?;
                self.u8(u8::from(value))
            }
            ValueRef::I64(value) => {
                self.u8(2)?;
                self.raw(&value.to_be_bytes())
            }
            ValueRef::Bytes(value) => {
                self.u8(3)?;
                self.bytes_u16(value, maximum_bytes)
            }
        }
    }

    fn predicate(&mut self, clauses: &[ClauseRef<'_>]) -> Result<(), Error> {
        if clauses.len() > MAX_CLAUSES {
            return Err(Error::Oversized);
        }
        self.u8(u8::try_from(clauses.len()).map_err(|_| Error::Oversized)?)?;
        for clause in clauses {
            self.u16(clause.attribute.0)?;
            self.u8(clause.operator as u8)?;
            self.value(clause.value, MAX_ATTRIBUTE_BYTES)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn predicate_is_typed_total_and_conjunctive() {
        let attributes = [
            AttributeRef {
                id: AttributeId(1),
                value: ValueRef::I64(22),
            },
            AttributeRef {
                id: AttributeId(2),
                value: ValueRef::Bool(true),
            },
        ];
        let mut env_bytes = [0u8; 128];
        let length = encode_environment(&mut env_bytes, &attributes).unwrap_or(0);
        let OperationRef::SetEnvironment(environment) =
            parse_operation(&env_bytes[..length]).unwrap_or_else(|_| unreachable!())
        else {
            unreachable!()
        };
        let clauses = [
            ClauseRef {
                attribute: AttributeId(1),
                operator: Operator::Ge,
                value: ValueRef::I64(20),
            },
            ClauseRef {
                attribute: AttributeId(2),
                operator: Operator::Eq,
                value: ValueRef::Bool(true),
            },
        ];
        let mut bytes = [0u8; 128];
        let length = encode_subscribe(&mut bytes, TypeId(7), &clauses).unwrap_or(0);
        let OperationRef::Subscribe { predicate, .. } =
            parse_operation(&bytes[..length]).unwrap_or_else(|_| unreachable!())
        else {
            unreachable!()
        };
        assert!(predicate.evaluate(environment));
    }

    fn evaluates(lhs: ValueRef<'_>, operator: Operator, rhs: ValueRef<'_>) -> bool {
        let attributes = [AttributeRef {
            id: AttributeId(1),
            value: lhs,
        }];
        let mut environment_bytes = [0u8; 128];
        let environment_length =
            encode_environment(&mut environment_bytes, &attributes).unwrap_or(0);
        let OperationRef::SetEnvironment(environment) =
            parse_operation(&environment_bytes[..environment_length])
                .unwrap_or_else(|_| unreachable!())
        else {
            unreachable!()
        };
        let clauses = [ClauseRef {
            attribute: AttributeId(1),
            operator,
            value: rhs,
        }];
        let mut predicate_bytes = [0u8; 128];
        let predicate_length =
            encode_subscribe(&mut predicate_bytes, TypeId(1), &clauses).unwrap_or(0);
        let OperationRef::Subscribe { predicate, .. } =
            parse_operation(&predicate_bytes[..predicate_length])
                .unwrap_or_else(|_| unreachable!())
        else {
            unreachable!()
        };
        predicate.evaluate(environment)
    }

    #[test]
    fn every_operator_handles_compatible_types() {
        for (operator, expected) in [
            (Operator::Eq, false),
            (Operator::Ne, true),
            (Operator::Lt, true),
            (Operator::Le, true),
            (Operator::Gt, false),
            (Operator::Ge, false),
        ] {
            assert_eq!(
                evaluates(ValueRef::I64(1), operator, ValueRef::I64(2)),
                expected
            );
            assert_eq!(
                evaluates(ValueRef::Bytes(b"a"), operator, ValueRef::Bytes(b"b")),
                expected
            );
            assert_eq!(
                evaluates(ValueRef::Bool(false), operator, ValueRef::Bool(true)),
                expected
            );
        }
    }

    #[test]
    fn every_operator_rejects_incompatible_types() {
        for operator in [
            Operator::Eq,
            Operator::Ne,
            Operator::Lt,
            Operator::Le,
            Operator::Gt,
            Operator::Ge,
        ] {
            for (lhs, rhs) in [
                (ValueRef::Bool(true), ValueRef::I64(1)),
                (ValueRef::Bool(true), ValueRef::Bytes(b"1")),
                (ValueRef::I64(1), ValueRef::Bool(true)),
                (ValueRef::I64(1), ValueRef::Bytes(b"1")),
                (ValueRef::Bytes(b"1"), ValueRef::Bool(true)),
                (ValueRef::Bytes(b"1"), ValueRef::I64(1)),
            ] {
                assert!(!evaluates(lhs, operator, rhs));
            }
        }
    }

    #[test]
    fn incompatible_values_do_not_satisfy_not_equal() {
        assert!(!evaluates(
            ValueRef::Bool(true),
            Operator::Ne,
            ValueRef::I64(1)
        ));
    }

    #[test]
    fn duplicate_environment_key_is_rejected() {
        let attributes = [
            AttributeRef {
                id: AttributeId(1),
                value: ValueRef::Bool(true),
            },
            AttributeRef {
                id: AttributeId(1),
                value: ValueRef::Bool(false),
            },
        ];
        assert_eq!(
            encode_environment(&mut [0u8; 64], &attributes),
            Err(Error::Malformed)
        );
    }

    #[test]
    fn one_shot_and_permanent_subscriptions_have_distinct_operations() {
        let clauses = [ClauseRef {
            attribute: AttributeId(1),
            operator: Operator::Eq,
            value: ValueRef::Bool(true),
        }];
        let mut one_shot = [0u8; 32];
        let one_shot_len = encode_subscribe(&mut one_shot, TypeId(7), &clauses).unwrap_or(0);
        let mut permanent = [0u8; 32];
        let permanent_len =
            encode_subscribe_permanent(&mut permanent, TypeId(7), &clauses).unwrap_or(0);

        assert!(matches!(
            parse_operation(&one_shot[..one_shot_len]),
            Ok(OperationRef::Subscribe {
                type_id: TypeId(7),
                ..
            })
        ));
        assert!(matches!(
            parse_operation(&permanent[..permanent_len]),
            Ok(OperationRef::SubscribePermanent {
                type_id: TypeId(7),
                ..
            })
        ));
        assert_ne!(one_shot[..one_shot_len], permanent[..permanent_len]);
    }

    proptest! {
        #[test]
        fn i64_predicate_matches_rust_total_order(lhs in any::<i64>(), rhs in any::<i64>()) {
            let attributes = [AttributeRef { id: AttributeId(1), value: ValueRef::I64(lhs) }];
            let mut environment_bytes = [0u8; 32];
            let environment_length = encode_environment(&mut environment_bytes, &attributes).unwrap_or(0);
            let environment = match parse_operation(&environment_bytes[..environment_length]) {
                Ok(OperationRef::SetEnvironment(environment)) => environment,
                _ => return Err(TestCaseError::fail("environment failed to parse")),
            };
            for (operator, expected) in [
                (Operator::Eq, lhs == rhs),
                (Operator::Ne, lhs != rhs),
                (Operator::Lt, lhs < rhs),
                (Operator::Le, lhs <= rhs),
                (Operator::Gt, lhs > rhs),
                (Operator::Ge, lhs >= rhs),
            ] {
                let clauses = [ClauseRef { attribute: AttributeId(1), operator, value: ValueRef::I64(rhs) }];
                let mut predicate_bytes = [0u8; 32];
                let predicate_length = encode_subscribe(&mut predicate_bytes, TypeId(1), &clauses).unwrap_or(0);
                let predicate = match parse_operation(&predicate_bytes[..predicate_length]) {
                    Ok(OperationRef::Subscribe { predicate, .. }) => predicate,
                    _ => return Err(TestCaseError::fail("predicate failed to parse")),
                };
                prop_assert_eq!(predicate.evaluate(environment), expected);
            }
        }
    }
}
