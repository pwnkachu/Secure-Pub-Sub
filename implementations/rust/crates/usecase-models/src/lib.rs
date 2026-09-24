#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Allocation-free typed application models for the bundled SecurePubSub use cases.
//!
//! Authorization attributes are explicitly marked as either self-declarable or CA-issued. Any
//! attribute used to grant access must be approved by the CA policy; the marker here documents
//! intent and the CA remains the enforcement point.

use core::marker::PhantomData;

use protocol_core::{
    AttributeId, AttributeRef, ClauseRef, MAX_ATTRIBUTE_BYTES, MAX_ATTRIBUTES, MAX_CLAUSES,
    Operator, TypeId, ValueRef,
};

/// Attribute provenance expected by the application model.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Authority {
    /// The authenticated Agent may update this operational value.
    SelfDeclared,
    /// The value must be approved and enforced by the CA.
    CaIssued,
}

/// Runtime attribute type used by schema validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttributeKind {
    /// Boolean.
    Bool,
    /// Signed 64-bit integer.
    I64,
    /// Bounded byte string.
    Bytes,
}

/// Builder or schema validation error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelError {
    /// A fixed protocol capacity would be exceeded.
    Capacity,
    /// The same attribute was supplied more than once.
    DuplicateAttribute,
    /// A byte string exceeds [`MAX_ATTRIBUTE_BYTES`].
    AttributeTooLong,
    /// An attribute is not part of the selected application domain.
    UnknownAttribute,
    /// A dynamically supplied value has the wrong type.
    WrongAttributeType,
}

/// Marker for a boolean attribute in one application domain.
#[derive(Clone, Copy)]
pub struct BoolAttribute<D> {
    id: AttributeId,
    authority: Authority,
    domain: PhantomData<fn() -> D>,
}

/// Marker for an integer attribute in one application domain.
#[derive(Clone, Copy)]
pub struct I64Attribute<D> {
    id: AttributeId,
    authority: Authority,
    domain: PhantomData<fn() -> D>,
}

/// Marker for a byte-string attribute in one application domain.
#[derive(Clone, Copy)]
pub struct BytesAttribute<D> {
    id: AttributeId,
    authority: Authority,
    domain: PhantomData<fn() -> D>,
}

macro_rules! attribute_impl {
    ($name:ident) => {
        impl<D> $name<D> {
            const fn new(id: u16, authority: Authority) -> Self {
                Self {
                    id: AttributeId(id),
                    authority,
                    domain: PhantomData,
                }
            }

            /// Raw stable protocol identifier.
            pub const fn id(self) -> AttributeId {
                self.id
            }

            /// Required source of authority.
            pub const fn authority(self) -> Authority {
                self.authority
            }
        }
    };
}

attribute_impl!(BoolAttribute);
attribute_impl!(I64Attribute);
attribute_impl!(BytesAttribute);

/// Sealed schema implemented by the three bundled application domains.
pub trait DomainSchema: private::Sealed {
    /// Returns the expected type and authority for a domain attribute.
    fn attribute(attribute: AttributeId) -> Option<(AttributeKind, Authority)>;
}

mod private {
    pub trait Sealed {}
}

/// Validates a dynamically obtained attribute against a selected domain schema.
pub fn validate_attribute<D: DomainSchema>(attribute: AttributeRef<'_>) -> Result<(), ModelError> {
    let (expected, _) = D::attribute(attribute.id).ok_or(ModelError::UnknownAttribute)?;
    let actual = match attribute.value {
        ValueRef::Bool(_) => AttributeKind::Bool,
        ValueRef::I64(_) => AttributeKind::I64,
        ValueRef::Bytes(value) => {
            if value.len() > MAX_ATTRIBUTE_BYTES {
                return Err(ModelError::AttributeTooLong);
            }
            AttributeKind::Bytes
        }
    };
    if expected != actual {
        return Err(ModelError::WrongAttributeType);
    }
    Ok(())
}

/// Fixed-capacity, allocation-free typed environment builder.
pub struct EnvironmentBuilder<'a, D> {
    entries: [AttributeRef<'a>; MAX_ATTRIBUTES],
    len: usize,
    domain: PhantomData<fn() -> D>,
}

impl<'a, D> EnvironmentBuilder<'a, D> {
    /// Creates an empty environment.
    pub const fn new() -> Self {
        Self {
            entries: [AttributeRef {
                id: AttributeId(0),
                value: ValueRef::Bool(false),
            }; MAX_ATTRIBUTES],
            len: 0,
            domain: PhantomData,
        }
    }

    /// Adds a typed boolean attribute.
    pub fn bool(
        &mut self,
        attribute: BoolAttribute<D>,
        value: bool,
    ) -> Result<&mut Self, ModelError> {
        self.push(attribute.id, ValueRef::Bool(value))
    }

    /// Adds a typed integer attribute.
    pub fn i64(&mut self, attribute: I64Attribute<D>, value: i64) -> Result<&mut Self, ModelError> {
        self.push(attribute.id, ValueRef::I64(value))
    }

    /// Adds a typed bounded byte-string attribute.
    pub fn bytes(
        &mut self,
        attribute: BytesAttribute<D>,
        value: &'a [u8],
    ) -> Result<&mut Self, ModelError> {
        if value.len() > MAX_ATTRIBUTE_BYTES {
            return Err(ModelError::AttributeTooLong);
        }
        self.push(attribute.id, ValueRef::Bytes(value))
    }

    fn push(&mut self, id: AttributeId, value: ValueRef<'a>) -> Result<&mut Self, ModelError> {
        if self.entries[..self.len].iter().any(|entry| entry.id == id) {
            return Err(ModelError::DuplicateAttribute);
        }
        let slot = self.entries.get_mut(self.len).ok_or(ModelError::Capacity)?;
        *slot = AttributeRef { id, value };
        self.len += 1;
        Ok(self)
    }

    /// Returns the bounded entries accepted by `agent-core`.
    pub fn attributes(&self) -> &[AttributeRef<'a>] {
        &self.entries[..self.len]
    }
}

impl<D> Default for EnvironmentBuilder<'_, D> {
    fn default() -> Self {
        Self::new()
    }
}

struct ClauseBuilder<'a, D> {
    clauses: [ClauseRef<'a>; MAX_CLAUSES],
    len: usize,
    domain: PhantomData<fn() -> D>,
}

impl<'a, D> ClauseBuilder<'a, D> {
    const fn new() -> Self {
        Self {
            clauses: [ClauseRef {
                attribute: AttributeId(0),
                operator: Operator::Eq,
                value: ValueRef::Bool(false),
            }; MAX_CLAUSES],
            len: 0,
            domain: PhantomData,
        }
    }

    fn push(
        &mut self,
        attribute: AttributeId,
        operator: Operator,
        value: ValueRef<'a>,
    ) -> Result<(), ModelError> {
        let slot = self.clauses.get_mut(self.len).ok_or(ModelError::Capacity)?;
        *slot = ClauseRef {
            attribute,
            operator,
            value,
        };
        self.len += 1;
        Ok(())
    }
}

macro_rules! predicate_builder {
    ($name:ident, $description:literal) => {
        #[doc = $description]
        pub struct $name<'a, D>(ClauseBuilder<'a, D>);

        impl<'a, D> $name<'a, D> {
            fn new() -> Self {
                Self(ClauseBuilder::new())
            }

            /// Adds a boolean clause.
            pub fn bool(
                &mut self,
                attribute: BoolAttribute<D>,
                operator: Operator,
                value: bool,
            ) -> Result<&mut Self, ModelError> {
                self.0.push(attribute.id, operator, ValueRef::Bool(value))?;
                Ok(self)
            }

            /// Adds an integer clause.
            pub fn i64(
                &mut self,
                attribute: I64Attribute<D>,
                operator: Operator,
                value: i64,
            ) -> Result<&mut Self, ModelError> {
                self.0.push(attribute.id, operator, ValueRef::I64(value))?;
                Ok(self)
            }

            /// Adds a bounded byte-string clause.
            pub fn bytes(
                &mut self,
                attribute: BytesAttribute<D>,
                operator: Operator,
                value: &'a [u8],
            ) -> Result<&mut Self, ModelError> {
                if value.len() > MAX_ATTRIBUTE_BYTES {
                    return Err(ModelError::AttributeTooLong);
                }
                self.0
                    .push(attribute.id, operator, ValueRef::Bytes(value))?;
                Ok(self)
            }

            /// Returns clauses accepted by `agent-core`.
            pub fn clauses(&self) -> &[ClauseRef<'a>] {
                &self.0.clauses[..self.0.len]
            }
        }
    };
}

predicate_builder!(
    SubscriptionBuilder,
    "Fixed-capacity typed builder for a subscriber predicate."
);
predicate_builder!(
    AudienceBuilder,
    "Fixed-capacity typed builder for a publisher audience."
);

/// Smart-building domain identifiers and typed builders.
#[cfg(feature = "smart-building")]
pub mod smart_building {
    use super::*;

    /// Smart-building schema marker.
    pub struct Domain;

    impl private::Sealed for Domain {}

    /// Environment builder for smart-building Agents.
    pub type Environment<'a> = EnvironmentBuilder<'a, Domain>;
    /// Subscription predicate builder with a mandatory building boundary.
    pub type Subscription<'a> = SubscriptionBuilder<'a, Domain>;
    /// Publication audience builder with a mandatory building boundary.
    pub type Audience<'a> = AudienceBuilder<'a, Domain>;

    /// Sensor reading event.
    pub const SENSOR_READING: TypeId = TypeId(0x1001);
    /// Temperature alert event.
    pub const TEMPERATURE_ALERT: TypeId = TypeId(0x1002);
    /// Fire alert event.
    pub const FIRE_ALERT: TypeId = TypeId(0x1003);
    /// Maintenance command event.
    pub const MAINTENANCE_COMMAND: TypeId = TypeId(0x1004);

    /// CA-issued building identifier.
    pub const BUILDING_ID: BytesAttribute<Domain> =
        BytesAttribute::new(0x1001, Authority::CaIssued);
    /// CA-issued floor identifier.
    pub const FLOOR_ID: I64Attribute<Domain> = I64Attribute::new(0x1002, Authority::CaIssued);
    /// CA-issued device class.
    pub const DEVICE_CLASS: I64Attribute<Domain> = I64Attribute::new(0x1003, Authority::CaIssued);
    /// CA-issued device certification flag.
    pub const CERTIFIED_DEVICE: BoolAttribute<Domain> =
        BoolAttribute::new(0x1004, Authority::CaIssued);
    /// CA-issued user role.
    pub const USER_ROLE: I64Attribute<Domain> = I64Attribute::new(0x1005, Authority::CaIssued);
    /// Self-declarable operational state.
    pub const OPERATIONAL: BoolAttribute<Domain> =
        BoolAttribute::new(0x1006, Authority::SelfDeclared);
    /// Self-declarable temperature in centi-degrees Celsius.
    pub const TEMPERATURE: I64Attribute<Domain> =
        I64Attribute::new(0x1007, Authority::SelfDeclared);
    /// Self-declarable occupancy count.
    pub const OCCUPANCY: I64Attribute<Domain> = I64Attribute::new(0x1008, Authority::SelfDeclared);
    /// CA-issued alert-zone identifier.
    pub const ALERT_ZONE: BytesAttribute<Domain> = BytesAttribute::new(0x1009, Authority::CaIssued);

    /// Smart-building device classes.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i64)]
    pub enum DeviceClass {
        /// Environmental sensor.
        Sensor = 1,
        /// Building control panel.
        ControlPanel = 2,
        /// Maintenance terminal.
        MaintenanceTerminal = 3,
    }

    /// Smart-building user roles.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i64)]
    pub enum UserRole {
        /// Building control operator.
        ControlOperator = 1,
        /// Authorized maintenance operator.
        MaintenanceOperator = 2,
        /// Unprivileged observer.
        Observer = 3,
    }

    /// Creates an empty typed environment.
    pub const fn environment<'a>() -> Environment<'a> {
        Environment::new()
    }

    /// Creates a subscription that can only match publishers in one building.
    pub fn subscription(building_id: &[u8]) -> Result<Subscription<'_>, ModelError> {
        let mut builder = Subscription::new();
        builder.bytes(BUILDING_ID, Operator::Eq, building_id)?;
        Ok(builder)
    }

    /// Creates an audience that can only match subscribers in one building.
    pub fn audience(building_id: &[u8]) -> Result<Audience<'_>, ModelError> {
        let mut builder = Audience::new();
        builder.bytes(BUILDING_ID, Operator::Eq, building_id)?;
        Ok(builder)
    }

    impl DomainSchema for Domain {
        fn attribute(attribute: AttributeId) -> Option<(AttributeKind, Authority)> {
            schema_entry(
                attribute,
                &[
                    (
                        BUILDING_ID.id(),
                        AttributeKind::Bytes,
                        BUILDING_ID.authority(),
                    ),
                    (FLOOR_ID.id(), AttributeKind::I64, FLOOR_ID.authority()),
                    (
                        DEVICE_CLASS.id(),
                        AttributeKind::I64,
                        DEVICE_CLASS.authority(),
                    ),
                    (
                        CERTIFIED_DEVICE.id(),
                        AttributeKind::Bool,
                        CERTIFIED_DEVICE.authority(),
                    ),
                    (USER_ROLE.id(), AttributeKind::I64, USER_ROLE.authority()),
                    (
                        OPERATIONAL.id(),
                        AttributeKind::Bool,
                        OPERATIONAL.authority(),
                    ),
                    (
                        TEMPERATURE.id(),
                        AttributeKind::I64,
                        TEMPERATURE.authority(),
                    ),
                    (OCCUPANCY.id(), AttributeKind::I64, OCCUPANCY.authority()),
                    (
                        ALERT_ZONE.id(),
                        AttributeKind::Bytes,
                        ALERT_ZONE.authority(),
                    ),
                ],
            )
        }
    }
}

/// Robot-swarm Collective Adaptive System identifiers and typed builders.
#[cfg(feature = "robot-swarm")]
pub mod robot_swarm {
    use super::*;

    /// Robot-swarm schema marker.
    pub struct Domain;
    impl private::Sealed for Domain {}

    /// Environment builder for swarm Agents.
    pub type Environment<'a> = EnvironmentBuilder<'a, Domain>;
    /// Subscription predicate builder with mandatory swarm and mission boundaries.
    pub type Subscription<'a> = SubscriptionBuilder<'a, Domain>;
    /// Audience builder with mandatory swarm and mission boundaries.
    pub type Audience<'a> = AudienceBuilder<'a, Domain>;

    /// Periodic drone telemetry.
    pub const DRONE_TELEMETRY: TypeId = TypeId(0x2001);
    /// Target detection report.
    pub const TARGET_DETECTED: TypeId = TypeId(0x2002);
    /// Mission-level command.
    pub const MISSION_COMMAND: TypeId = TypeId(0x2003);
    /// Assignment to one preselected robot.
    pub const TASK_ASSIGNMENT: TypeId = TypeId(0x2004);
    /// Formation update.
    pub const FORMATION_UPDATE: TypeId = TypeId(0x2005);
    /// Emergency alert.
    pub const EMERGENCY_ALERT: TypeId = TypeId(0x2006);

    /// CA-issued swarm identifier.
    pub const SWARM_ID: BytesAttribute<Domain> = BytesAttribute::new(0x2001, Authority::CaIssued);
    /// CA-issued mission epoch.
    pub const MISSION_EPOCH: I64Attribute<Domain> = I64Attribute::new(0x2002, Authority::CaIssued);
    /// CA-issued robot role.
    pub const ROBOT_ROLE: I64Attribute<Domain> = I64Attribute::new(0x2003, Authority::CaIssued);
    /// CA-issued privileged capability.
    pub const CAPABILITY: I64Attribute<Domain> = I64Attribute::new(0x2004, Authority::CaIssued);
    /// CA-issued payload capacity in grams.
    pub const PAYLOAD_CAPACITY: I64Attribute<Domain> =
        I64Attribute::new(0x2005, Authority::CaIssued);
    /// Self-declarable operational state.
    pub const OPERATIONAL: BoolAttribute<Domain> =
        BoolAttribute::new(0x2006, Authority::SelfDeclared);
    /// Self-declarable battery percentage.
    pub const BATTERY_LEVEL: I64Attribute<Domain> =
        I64Attribute::new(0x2007, Authority::SelfDeclared);
    /// Self-declarable current zone.
    pub const ZONE: BytesAttribute<Domain> = BytesAttribute::new(0x2008, Authority::SelfDeclared);
    /// Task claim assignable only after coordinator or CA approval.
    pub const ASSIGNED_TASK: BytesAttribute<Domain> =
        BytesAttribute::new(0x2009, Authority::CaIssued);
    /// CA-issued identity selector containing the 16 binary bytes of an `AgentId`.
    pub const RECIPIENT_ID: BytesAttribute<Domain> =
        BytesAttribute::new(0x200a, Authority::CaIssued);

    /// Swarm roles.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i64)]
    pub enum RobotRole {
        /// Mission coordinator.
        Coordinator = 1,
        /// Reconnaissance robot.
        Scout = 2,
        /// Task responder.
        Responder = 3,
        /// Network relay.
        Relay = 4,
    }

    /// Privileged robot capabilities.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i64)]
    pub enum Capability {
        /// RGB camera.
        RgbCamera = 1,
        /// Thermal camera.
        ThermalCamera = 2,
        /// Payload transport.
        Transport = 3,
        /// Manipulator.
        Manipulation = 4,
        /// Network relay.
        NetworkRelay = 5,
    }

    /// Creates an empty typed environment.
    pub const fn environment<'a>() -> Environment<'a> {
        Environment::new()
    }

    /// Creates a subscription constrained to one swarm and mission epoch.
    pub fn subscription(
        swarm_id: &[u8],
        mission_epoch: i64,
    ) -> Result<Subscription<'_>, ModelError> {
        let mut builder = Subscription::new();
        builder.bytes(SWARM_ID, Operator::Eq, swarm_id)?.i64(
            MISSION_EPOCH,
            Operator::Eq,
            mission_epoch,
        )?;
        Ok(builder)
    }

    /// Creates an audience constrained to one swarm and mission epoch.
    pub fn audience(swarm_id: &[u8], mission_epoch: i64) -> Result<Audience<'_>, ModelError> {
        let mut builder = Audience::new();
        builder.bytes(SWARM_ID, Operator::Eq, swarm_id)?.i64(
            MISSION_EPOCH,
            Operator::Eq,
            mission_epoch,
        )?;
        Ok(builder)
    }

    impl DomainSchema for Domain {
        fn attribute(attribute: AttributeId) -> Option<(AttributeKind, Authority)> {
            schema_entry(
                attribute,
                &[
                    (SWARM_ID.id(), AttributeKind::Bytes, SWARM_ID.authority()),
                    (
                        MISSION_EPOCH.id(),
                        AttributeKind::I64,
                        MISSION_EPOCH.authority(),
                    ),
                    (ROBOT_ROLE.id(), AttributeKind::I64, ROBOT_ROLE.authority()),
                    (CAPABILITY.id(), AttributeKind::I64, CAPABILITY.authority()),
                    (
                        PAYLOAD_CAPACITY.id(),
                        AttributeKind::I64,
                        PAYLOAD_CAPACITY.authority(),
                    ),
                    (
                        OPERATIONAL.id(),
                        AttributeKind::Bool,
                        OPERATIONAL.authority(),
                    ),
                    (
                        BATTERY_LEVEL.id(),
                        AttributeKind::I64,
                        BATTERY_LEVEL.authority(),
                    ),
                    (ZONE.id(), AttributeKind::Bytes, ZONE.authority()),
                    (
                        ASSIGNED_TASK.id(),
                        AttributeKind::Bytes,
                        ASSIGNED_TASK.authority(),
                    ),
                    (
                        RECIPIENT_ID.id(),
                        AttributeKind::Bytes,
                        RECIPIENT_ID.authority(),
                    ),
                ],
            )
        }
    }
}

/// Multi-tenant event-bus identifiers and typed builders.
#[cfg(feature = "multi-tenant")]
pub mod multi_tenant {
    use super::*;

    /// Multi-tenant schema marker.
    pub struct Domain;
    impl private::Sealed for Domain {}

    /// Environment builder for services and consumers.
    pub type Environment<'a> = EnvironmentBuilder<'a, Domain>;
    /// Subscription builder with a mandatory tenant boundary.
    pub type Subscription<'a> = SubscriptionBuilder<'a, Domain>;
    /// Audience builder with a mandatory tenant boundary.
    pub type Audience<'a> = AudienceBuilder<'a, Domain>;

    /// Business domain event.
    pub const DOMAIN_EVENT: TypeId = TypeId(0x3001);
    /// Audit event.
    pub const AUDIT_EVENT: TypeId = TypeId(0x3002);
    /// Deployment lifecycle event.
    pub const DEPLOYMENT_EVENT: TypeId = TypeId(0x3003);
    /// Security alert.
    pub const SECURITY_ALERT: TypeId = TypeId(0x3004);

    /// CA-issued tenant identifier.
    pub const TENANT_ID: BytesAttribute<Domain> = BytesAttribute::new(0x3001, Authority::CaIssued);
    /// CA-issued service identifier.
    pub const SERVICE_ID: BytesAttribute<Domain> = BytesAttribute::new(0x3002, Authority::CaIssued);
    /// CA-issued deployment environment.
    pub const DEPLOYMENT_ENVIRONMENT: I64Attribute<Domain> =
        I64Attribute::new(0x3003, Authority::CaIssued);
    /// CA-issued service role.
    pub const SERVICE_ROLE: I64Attribute<Domain> = I64Attribute::new(0x3004, Authority::CaIssued);
    /// CA-issued numeric clearance level.
    pub const CLEARANCE_LEVEL: I64Attribute<Domain> =
        I64Attribute::new(0x3005, Authority::CaIssued);
    /// Self-declarable service health state.
    pub const SERVICE_HEALTH: BoolAttribute<Domain> =
        BoolAttribute::new(0x3006, Authority::SelfDeclared);
    /// CA-issued deployment region.
    pub const REGION: BytesAttribute<Domain> = BytesAttribute::new(0x3007, Authority::CaIssued);

    /// Deployment environments.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i64)]
    pub enum DeploymentEnvironment {
        /// Production.
        Production = 1,
        /// Staging.
        Staging = 2,
    }

    /// Service roles.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    #[repr(i64)]
    pub enum ServiceRole {
        /// Event publisher.
        Publisher = 1,
        /// Business event consumer.
        Consumer = 2,
        /// Audit consumer.
        Auditor = 3,
        /// Security operations consumer.
        SecurityOperator = 4,
    }

    /// Creates an empty typed environment.
    pub const fn environment<'a>() -> Environment<'a> {
        Environment::new()
    }

    /// Creates a subscription constrained to exactly one tenant.
    pub fn subscription(tenant_id: &[u8]) -> Result<Subscription<'_>, ModelError> {
        let mut builder = Subscription::new();
        builder.bytes(TENANT_ID, Operator::Eq, tenant_id)?;
        Ok(builder)
    }

    /// Creates an audience constrained to exactly one tenant.
    pub fn audience(tenant_id: &[u8]) -> Result<Audience<'_>, ModelError> {
        let mut builder = Audience::new();
        builder.bytes(TENANT_ID, Operator::Eq, tenant_id)?;
        Ok(builder)
    }

    impl DomainSchema for Domain {
        fn attribute(attribute: AttributeId) -> Option<(AttributeKind, Authority)> {
            schema_entry(
                attribute,
                &[
                    (TENANT_ID.id(), AttributeKind::Bytes, TENANT_ID.authority()),
                    (
                        SERVICE_ID.id(),
                        AttributeKind::Bytes,
                        SERVICE_ID.authority(),
                    ),
                    (
                        DEPLOYMENT_ENVIRONMENT.id(),
                        AttributeKind::I64,
                        DEPLOYMENT_ENVIRONMENT.authority(),
                    ),
                    (
                        SERVICE_ROLE.id(),
                        AttributeKind::I64,
                        SERVICE_ROLE.authority(),
                    ),
                    (
                        CLEARANCE_LEVEL.id(),
                        AttributeKind::I64,
                        CLEARANCE_LEVEL.authority(),
                    ),
                    (
                        SERVICE_HEALTH.id(),
                        AttributeKind::Bool,
                        SERVICE_HEALTH.authority(),
                    ),
                    (REGION.id(), AttributeKind::Bytes, REGION.authority()),
                ],
            )
        }
    }
}

fn schema_entry(
    wanted: AttributeId,
    entries: &[(AttributeId, AttributeKind, Authority)],
) -> Option<(AttributeKind, Authority)> {
    entries
        .iter()
        .find(|(id, _, _)| *id == wanted)
        .map(|(_, kind, authority)| (*kind, *authority))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(
        feature = "smart-building",
        feature = "robot-swarm",
        feature = "multi-tenant"
    ))]
    fn domains_are_disjoint_and_authority_is_documented() {
        assert_ne!(smart_building::BUILDING_ID.id(), robot_swarm::SWARM_ID.id());
        assert_ne!(robot_swarm::SWARM_ID.id(), multi_tenant::TENANT_ID.id());
        assert_eq!(smart_building::BUILDING_ID.authority(), Authority::CaIssued);
        assert_eq!(
            smart_building::TEMPERATURE.authority(),
            Authority::SelfDeclared
        );
    }

    #[test]
    #[cfg(feature = "smart-building")]
    fn dynamic_type_validation_fails_closed() {
        assert_eq!(
            validate_attribute::<smart_building::Domain>(AttributeRef {
                id: smart_building::CERTIFIED_DEVICE.id(),
                value: ValueRef::I64(1),
            }),
            Err(ModelError::WrongAttributeType)
        );
    }

    #[test]
    #[cfg(all(
        feature = "smart-building",
        feature = "robot-swarm",
        feature = "multi-tenant"
    ))]
    fn mandatory_domain_clauses_are_inserted() {
        let building = smart_building::subscription(b"north").unwrap_or_else(|_| unreachable!());
        let swarm = robot_swarm::audience(b"alpha", 7).unwrap_or_else(|_| unreachable!());
        let tenant = multi_tenant::subscription(b"tenant-a").unwrap_or_else(|_| unreachable!());
        assert_eq!(building.clauses().len(), 1);
        assert_eq!(swarm.clauses().len(), 2);
        assert_eq!(tenant.clauses().len(), 1);
    }

    #[test]
    #[cfg(feature = "smart-building")]
    fn builders_enforce_protocol_bounds_without_allocation() {
        let oversized = [0u8; MAX_ATTRIBUTE_BYTES + 1];
        assert!(matches!(
            smart_building::audience(&oversized),
            Err(ModelError::AttributeTooLong)
        ));
        let mut environment = smart_building::environment();
        assert!(
            environment
                .bytes(smart_building::BUILDING_ID, b"north")
                .is_ok()
        );
        assert_eq!(
            environment
                .bytes(smart_building::BUILDING_ID, b"south")
                .map(|_| ()),
            Err(ModelError::DuplicateAttribute)
        );
    }

    #[test]
    #[cfg(feature = "robot-swarm")]
    fn recipient_id_uses_binary_identity_bytes() {
        let binary = [0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3];
        let ascii = b"20000000000000000000000000000003";
        let mut environment = robot_swarm::environment();
        assert!(
            environment
                .bytes(robot_swarm::RECIPIENT_ID, &binary)
                .is_ok()
        );
        let mut audience = robot_swarm::audience(b"alpha", 7).unwrap_or_else(|_| unreachable!());
        assert!(
            audience
                .bytes(robot_swarm::RECIPIENT_ID, Operator::Eq, &binary)
                .is_ok()
        );
        let recipient = environment
            .attributes()
            .iter()
            .find(|attribute| attribute.id == robot_swarm::RECIPIENT_ID.id())
            .map(|attribute| attribute.value);
        assert_eq!(recipient, Some(ValueRef::Bytes(binary.as_slice())));
        assert_ne!(recipient, Some(ValueRef::Bytes(ascii)));
    }
}
