#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Tokio TCP framing with strict envelope bounds, timeouts, and backpressure.

use std::{
    io,
    ops::{Deref, DerefMut},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use protocol_core::{AgentId, MAX_FRAME_LEN};
use thiserror::Error;
use tokio::{net::TcpStream, time::timeout};
use tokio_util::codec::{Framed, LengthDelimitedCodec};

/// Maximum control frame length (a hello is exactly 16 bytes).
pub const HELLO_LEN: usize = 16;

/// Operating-system CSPRNG adapter.
pub struct SystemRandom(rand_chacha::ChaCha20Rng);

impl SystemRandom {
    /// Seeds a userspace CSPRNG from the operating system.
    pub fn new() -> Result<Self, TransportError> {
        let mut seed = [0u8; 32];
        getrandom::fill(&mut seed).map_err(|_| TransportError::Random)?;
        Ok(Self(rand_core::SeedableRng::from_seed(seed)))
    }
}

impl Deref for SystemRandom {
    type Target = rand_chacha::ChaCha20Rng;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for SystemRandom {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// Transport failures contain no payload data.
#[derive(Debug, Error)]
pub enum TransportError {
    /// OS CSPRNG initialization failed.
    #[error("randomness initialization failed")]
    Random,
    /// I/O failure.
    #[error("transport I/O failure")]
    Io(#[from] io::Error),
    /// Deadline elapsed.
    #[error("transport timeout")]
    Timeout,
    /// Invalid or oversized frame.
    #[error("invalid transport frame")]
    InvalidFrame,
    /// Peer closed the stream.
    #[error("peer disconnected")]
    Disconnected,
}

/// A bounded length-delimited TCP stream.
pub struct FramedTransport {
    framed: Framed<TcpStream, LengthDelimitedCodec>,
    deadline: Duration,
}

impl FramedTransport {
    /// Wraps a connected socket. Length prefixes are unsigned big-endian u32.
    pub fn new(stream: TcpStream, deadline: Duration) -> Self {
        let codec = LengthDelimitedCodec::builder()
            .length_field_type::<u32>()
            .max_frame_length(MAX_FRAME_LEN)
            .new_codec();
        Self {
            framed: Framed::new(stream, codec),
            deadline,
        }
    }

    /// Connects with a deadline.
    pub async fn connect(address: &str, deadline: Duration) -> Result<Self, TransportError> {
        let stream = timeout(deadline, TcpStream::connect(address))
            .await
            .map_err(|_| TransportError::Timeout)??;
        stream.set_nodelay(true)?;
        Ok(Self::new(stream, deadline))
    }

    /// Sends one bounded frame with backpressure and timeout.
    pub async fn send(&mut self, frame: &[u8]) -> Result<(), TransportError> {
        if frame.len() > MAX_FRAME_LEN {
            return Err(TransportError::InvalidFrame);
        }
        timeout(
            self.deadline,
            self.framed.send(Bytes::copy_from_slice(frame)),
        )
        .await
        .map_err(|_| TransportError::Timeout)??;
        Ok(())
    }

    /// Receives one bounded frame.
    pub async fn receive(&mut self) -> Result<Vec<u8>, TransportError> {
        match timeout(self.deadline, self.framed.next()).await {
            Err(_) => Err(TransportError::Timeout),
            Ok(None) => Err(TransportError::Disconnected),
            Ok(Some(Err(error))) => Err(TransportError::Io(error)),
            Ok(Some(Ok(bytes))) if bytes.len() <= MAX_FRAME_LEN => Ok(bytes.to_vec()),
            Ok(Some(Ok(_))) => Err(TransportError::InvalidFrame),
        }
    }

    /// Receives one bounded frame into caller-owned storage.
    ///
    /// This is the adapter used by the allocation-free Agent API. The Tokio codec itself still
    /// owns a desktop heap buffer internally; embedded transports can implement
    /// `protocol_core::AsyncTransport` without that allocation.
    pub async fn receive_into(&mut self, output: &mut [u8]) -> Result<usize, TransportError> {
        let bytes = self.receive().await?;
        let destination = output
            .get_mut(..bytes.len())
            .ok_or(TransportError::InvalidFrame)?;
        destination.copy_from_slice(&bytes);
        Ok(bytes.len())
    }

    /// Sends the connection identity hello. It is routing metadata, not authentication.
    pub async fn send_hello(&mut self, identity: AgentId) -> Result<(), TransportError> {
        self.send(&identity.0).await
    }

    /// Receives and validates the fixed-size hello.
    pub async fn receive_hello(&mut self) -> Result<AgentId, TransportError> {
        let bytes = self.receive().await?;
        let identity = bytes.try_into().map_err(|_| TransportError::InvalidFrame)?;
        Ok(AgentId(identity))
    }

    /// Splits into Tokio codec halves for concurrent read/write loops.
    pub fn into_inner(self) -> Framed<TcpStream, LengthDelimitedCodec> {
        self.framed
    }
}

impl protocol_core::AsyncTransport for FramedTransport {
    type Error = TransportError;

    fn send(
        &mut self,
        frame: &[u8],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> {
        FramedTransport::send(self, frame)
    }

    fn receive(
        &mut self,
        output: &mut [u8],
    ) -> impl core::future::Future<Output = Result<usize, Self::Error>> {
        self.receive_into(output)
    }
}
