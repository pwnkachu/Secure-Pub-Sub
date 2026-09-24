#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Embassy firmware component for the smart-building sensor Agent.
//!
//! Board firmware supplies provisioned keys, an initialized Embassy TCP socket,
//! a hardware-seeded cryptographic RNG and one `MAX_FRAME_LEN` buffer. This
//! component performs no allocation and communicates with the existing Tokio
//! Broker and CA using [`embassy_transport::EmbassyFramedTransport`].

use agent_core::Agent;
use embassy_transport::{EmbassyFramedTransport, EmbassyIo, EmbassyTransportError};
use protocol_core::{CryptoRandom, Error, MAX_FRAME_LEN, Operator};
use usecase_models::{ModelError, smart_building as model};

/// Static configuration provisioned for one embedded building sensor.
#[derive(Clone, Copy, Debug)]
pub struct SensorConfig<'a> {
    /// CA-issued building boundary.
    pub building_id: &'a [u8],
    /// CA-issued alert zone.
    pub alert_zone: &'a [u8],
    /// CA-issued floor number.
    pub floor_id: i64,
    /// Initial operational state.
    pub operational: bool,
    /// Initial temperature in centi-degrees Celsius.
    pub initial_temperature: i64,
}

/// Failure from the embedded smart-building Agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorError<E> {
    /// Typed use-case data exceeded a bound or violated its schema.
    Model(ModelError),
    /// SecurePubSub envelope construction failed.
    Protocol(Error),
    /// Embassy transport failed; the socket must be reconnected.
    Transport(EmbassyTransportError<E>),
}

/// Allocation-free smart-building sensor driven by board firmware.
pub struct EmbassySensorAgent<'a> {
    agent: Agent,
    config: SensorConfig<'a>,
}

impl<'a> EmbassySensorAgent<'a> {
    /// Creates a sensor from provisioned Agent keys and application policy data.
    pub const fn new(agent: Agent, config: SensorConfig<'a>) -> Self {
        Self { agent, config }
    }

    /// Returns the underlying protocol Agent.
    pub const fn agent(&self) -> &Agent {
        &self.agent
    }

    /// Sends the broker hello followed by the sensor's complete environment.
    pub async fn initialize<S: EmbassyIo>(
        &self,
        transport: &mut EmbassyFramedTransport<S>,
        rng: &mut impl CryptoRandom,
        frame: &mut [u8; MAX_FRAME_LEN],
    ) -> Result<(), SensorError<S::Error>> {
        transport
            .send_hello(self.agent.id())
            .await
            .map_err(SensorError::Transport)?;

        let mut environment = model::environment();
        environment
            .bytes(model::BUILDING_ID, self.config.building_id)
            .map_err(SensorError::Model)?
            .bytes(model::ALERT_ZONE, self.config.alert_zone)
            .map_err(SensorError::Model)?
            .i64(model::FLOOR_ID, self.config.floor_id)
            .map_err(SensorError::Model)?
            .i64(model::DEVICE_CLASS, model::DeviceClass::Sensor as i64)
            .map_err(SensorError::Model)?
            .bool(model::CERTIFIED_DEVICE, true)
            .map_err(SensorError::Model)?
            .bool(model::OPERATIONAL, self.config.operational)
            .map_err(SensorError::Model)?
            .i64(model::TEMPERATURE, self.config.initial_temperature)
            .map_err(SensorError::Model)?;
        let length = self
            .agent
            .set_environment_into(frame, environment.attributes(), rng)
            .map_err(SensorError::Protocol)?;
        transport
            .send(&frame[..length])
            .await
            .map_err(SensorError::Transport)
    }

    /// Publishes one sensor reading to control operators in the same building.
    pub async fn publish_temperature<S: EmbassyIo>(
        &self,
        temperature_centi_celsius: i64,
        transport: &mut EmbassyFramedTransport<S>,
        rng: &mut impl CryptoRandom,
        frame: &mut [u8; MAX_FRAME_LEN],
    ) -> Result<(), SensorError<S::Error>> {
        let mut audience = model::audience(self.config.building_id).map_err(SensorError::Model)?;
        audience
            .i64(
                model::USER_ROLE,
                Operator::Eq,
                model::UserRole::ControlOperator as i64,
            )
            .map_err(SensorError::Model)?;
        let value = temperature_centi_celsius.to_be_bytes();
        let length = self
            .agent
            .publish_into(
                frame,
                model::SENSOR_READING,
                audience.clauses(),
                &value,
                rng,
            )
            .map_err(SensorError::Protocol)?;
        transport
            .send(&frame[..length])
            .await
            .map_err(SensorError::Transport)
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use core::convert::Infallible;
    use std::vec::Vec;

    use agent_core::{AgentKeys, CaPublicKeys};
    use embedded_io_async::{Read, Write};
    use protocol_core::{AgentId, MessageType, parse_envelope};
    use rand_chacha::rand_core::SeedableRng;

    use super::*;

    #[derive(Default)]
    struct CaptureIo(Vec<u8>);

    impl embedded_io_async::ErrorType for CaptureIo {
        type Error = Infallible;
    }

    impl Read for CaptureIo {
        async fn read(&mut self, _output: &mut [u8]) -> Result<usize, Self::Error> {
            Ok(0)
        }
    }

    impl Write for CaptureIo {
        async fn write(&mut self, input: &[u8]) -> Result<usize, Self::Error> {
            self.0.extend_from_slice(input);
            Ok(input.len())
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    fn next_frame(bytes: &mut &[u8]) -> Vec<u8> {
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap_or_default()) as usize;
        let frame = bytes[4..4 + length].to_vec();
        *bytes = &bytes[4 + length..];
        frame
    }

    #[test]
    fn sensor_uses_embassy_transport_for_environment_and_publication() {
        futures_lite::future::block_on(async {
            let ca_secret = x25519_dalek::StaticSecret::from([41; 32]);
            let agent = Agent::new(
                AgentId([7; 16]),
                AgentKeys::from_seeds([11; 32], [12; 32]),
                CaPublicKeys {
                    ed25519: [31; 32],
                    x25519: x25519_dalek::PublicKey::from(&ca_secret).to_bytes(),
                },
            );
            let sensor = EmbassySensorAgent::new(
                agent,
                SensorConfig {
                    building_id: b"north",
                    alert_zone: b"zone-a",
                    floor_id: 2,
                    operational: true,
                    initial_temperature: 2_150,
                },
            );
            let mut transport = EmbassyFramedTransport::new(CaptureIo::default());
            let mut rng = rand_chacha::ChaCha20Rng::from_seed([91; 32]);
            let mut frame = [0u8; MAX_FRAME_LEN];

            assert!(
                sensor
                    .initialize(&mut transport, &mut rng, &mut frame)
                    .await
                    .is_ok()
            );
            assert!(
                sensor
                    .publish_temperature(2_225, &mut transport, &mut rng, &mut frame)
                    .await
                    .is_ok()
            );

            let captured = transport.into_inner();
            let mut bytes = captured.0.as_slice();
            assert_eq!(next_frame(&mut bytes), sensor.agent().id().0);
            let environment = next_frame(&mut bytes);
            assert_eq!(
                parse_envelope(&environment).map(|envelope| envelope.message_type),
                Ok(MessageType::SetEnvironment)
            );
            let publication = next_frame(&mut bytes);
            assert_eq!(
                parse_envelope(&publication).map(|envelope| envelope.message_type),
                Ok(MessageType::Publish)
            );
            assert!(bytes.is_empty());
        });
    }
}
