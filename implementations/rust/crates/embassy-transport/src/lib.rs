#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Allocation-free SecurePubSub framing for Embassy Agents.
//!
//! [`EmbassyFramedTransport`] accepts any full-duplex stream implementing
//! `embedded_io_async`, including `embassy_net::tcp::TcpSocket`. Frames use the
//! same unsigned big-endian `u32` length prefix as the Tokio transport used by
//! the Broker and CA.

use core::fmt;

use embassy_time::{Duration, Instant, with_timeout};
use embedded_io_async::{Read, Write};
use protocol_core::{AgentId, AsyncTransport, Clock, MAX_FRAME_LEN};

/// Full-duplex asynchronous I/O accepted by the Embassy adapter.
///
/// Embassy TCP sockets implement both parent traits directly. The marker keeps
/// firmware APIs independent from a concrete network driver or MCU family.
pub trait EmbassyIo: Read + Write {}

impl<T: Read + Write + ?Sized> EmbassyIo for T {}

/// Failure returned by the allocation-free framed transport.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmbassyTransportError<E> {
    /// The underlying Embassy/embedded-I/O stream failed.
    Io(E),
    /// The configured Embassy deadline elapsed.
    Timeout,
    /// The peer closed the stream before a complete frame arrived.
    Disconnected,
    /// A frame was larger than the protocol or caller-owned buffer.
    InvalidFrame,
}

impl<E: fmt::Display> fmt::Display for EmbassyTransportError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "embedded transport I/O failure: {error}"),
            Self::Timeout => formatter.write_str("embedded transport timeout"),
            Self::Disconnected => formatter.write_str("embedded transport disconnected"),
            Self::InvalidFrame => formatter.write_str("invalid embedded transport frame"),
        }
    }
}

/// Monotonic protocol clock backed by the Embassy time driver.
#[derive(Clone, Copy, Debug, Default)]
pub struct EmbassyClock;

impl Clock for EmbassyClock {
    fn now_seconds(&self) -> u64 {
        Instant::now().as_secs()
    }
}

/// Bounded, allocation-free framing over an Embassy-compatible stream.
///
/// The caller owns the socket and all receive storage. A timeout is terminal:
/// cancelling a partially completed framed write can leave the byte stream at a
/// frame boundary that cannot be recovered safely, so firmware must drop the
/// connection and reconnect after any error.
pub struct EmbassyFramedTransport<S> {
    stream: S,
    deadline: Option<Duration>,
}

impl<S> EmbassyFramedTransport<S> {
    /// Wraps a connected stream without an adapter-level deadline.
    pub const fn new(stream: S) -> Self {
        Self {
            stream,
            deadline: None,
        }
    }

    /// Wraps a connected stream and bounds each complete frame operation.
    pub const fn with_timeout(stream: S, deadline: Duration) -> Self {
        Self {
            stream,
            deadline: Some(deadline),
        }
    }

    /// Returns the connected stream.
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: EmbassyIo> EmbassyFramedTransport<S> {
    async fn write_frame(&mut self, frame: &[u8]) -> Result<(), S::Error> {
        let prefix = (frame.len() as u32).to_be_bytes();
        self.stream.write_all(&prefix).await?;
        self.stream.write_all(frame).await?;
        self.stream.flush().await
    }

    async fn read_exact(&mut self, mut output: &mut [u8]) -> Result<(), ReadFailure<S::Error>> {
        while !output.is_empty() {
            let read = self.stream.read(output).await.map_err(ReadFailure::Io)?;
            if read == 0 {
                return Err(ReadFailure::Disconnected);
            }
            output = &mut output[read..];
        }
        Ok(())
    }

    async fn read_frame(&mut self, output: &mut [u8]) -> Result<usize, ReadFailure<S::Error>> {
        let mut prefix = [0u8; 4];
        self.read_exact(&mut prefix).await?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > MAX_FRAME_LEN || length > output.len() {
            return Err(ReadFailure::InvalidFrame);
        }
        self.read_exact(&mut output[..length]).await?;
        Ok(length)
    }

    /// Sends one bounded SecurePubSub envelope.
    pub async fn send(&mut self, frame: &[u8]) -> Result<(), EmbassyTransportError<S::Error>> {
        if frame.len() > MAX_FRAME_LEN {
            return Err(EmbassyTransportError::InvalidFrame);
        }
        let deadline = self.deadline;
        let result = match deadline {
            Some(deadline) => with_timeout(deadline, self.write_frame(frame))
                .await
                .map_err(|_| EmbassyTransportError::Timeout)?,
            None => self.write_frame(frame).await,
        };
        result.map_err(EmbassyTransportError::Io)
    }

    /// Receives one bounded envelope into caller-owned storage.
    pub async fn receive(
        &mut self,
        output: &mut [u8],
    ) -> Result<usize, EmbassyTransportError<S::Error>> {
        let deadline = self.deadline;
        let result = match deadline {
            Some(deadline) => with_timeout(deadline, self.read_frame(output))
                .await
                .map_err(|_| EmbassyTransportError::Timeout)?,
            None => self.read_frame(output).await,
        };
        result.map_err(|error| match error {
            ReadFailure::Io(error) => EmbassyTransportError::Io(error),
            ReadFailure::Disconnected => EmbassyTransportError::Disconnected,
            ReadFailure::InvalidFrame => EmbassyTransportError::InvalidFrame,
        })
    }

    /// Sends the fixed Agent identity hello expected by the Tokio broker.
    pub async fn send_hello(
        &mut self,
        identity: AgentId,
    ) -> Result<(), EmbassyTransportError<S::Error>> {
        self.send(&identity.0).await
    }
}

impl<S: EmbassyIo> AsyncTransport for EmbassyFramedTransport<S> {
    type Error = EmbassyTransportError<S::Error>;

    fn send(
        &mut self,
        frame: &[u8],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>> {
        EmbassyFramedTransport::send(self, frame)
    }

    fn receive(
        &mut self,
        output: &mut [u8],
    ) -> impl core::future::Future<Output = Result<usize, Self::Error>> {
        EmbassyFramedTransport::receive(self, output)
    }
}

enum ReadFailure<E> {
    Io(E),
    Disconnected,
    InvalidFrame,
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests {
    use core::convert::Infallible;
    use std::{collections::VecDeque, vec, vec::Vec};

    use super::*;

    struct FragmentedIo {
        input: VecDeque<u8>,
        output: Vec<u8>,
        chunk: usize,
    }

    impl FragmentedIo {
        fn new(input: &[u8], chunk: usize) -> Self {
            Self {
                input: input.iter().copied().collect(),
                output: Vec::new(),
                chunk,
            }
        }
    }

    impl embedded_io_async::ErrorType for FragmentedIo {
        type Error = Infallible;
    }

    impl Read for FragmentedIo {
        async fn read(&mut self, output: &mut [u8]) -> Result<usize, Self::Error> {
            let count = output.len().min(self.chunk).min(self.input.len());
            for destination in &mut output[..count] {
                *destination = self.input.pop_front().unwrap_or_default();
            }
            Ok(count)
        }
    }

    impl Write for FragmentedIo {
        async fn write(&mut self, input: &[u8]) -> Result<usize, Self::Error> {
            let count = input.len().min(self.chunk);
            self.output.extend_from_slice(&input[..count]);
            Ok(count)
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn framing_matches_tokio_length_delimited_codec_across_short_io() {
        futures_lite::future::block_on(async {
            let payload = [7u8, 8, 9];
            let encoded = [0u8, 0, 0, 3, 7, 8, 9];
            let io = FragmentedIo::new(&encoded, 1);
            let mut transport = EmbassyFramedTransport::new(io);
            let mut output = [0u8; 8];
            assert_eq!(transport.receive(&mut output).await, Ok(3));
            assert_eq!(&output[..3], &payload);
            assert_eq!(transport.send(&payload).await, Ok(()));
            assert_eq!(transport.into_inner().output, encoded);
        });
    }

    #[test]
    fn oversized_prefix_is_rejected_before_payload_read() {
        futures_lite::future::block_on(async {
            let encoded = ((MAX_FRAME_LEN as u32) + 1).to_be_bytes();
            let io = FragmentedIo::new(&encoded, 4);
            let mut transport = EmbassyFramedTransport::new(io);
            let mut output = vec![0u8; MAX_FRAME_LEN];
            assert_eq!(
                transport.receive(&mut output).await,
                Err(EmbassyTransportError::InvalidFrame)
            );
        });
    }

    #[test]
    fn embassy_tcp_socket_satisfies_adapter_contract() {
        fn assert_io<T: EmbassyIo>() {}
        assert_io::<embassy_net::tcp::TcpSocket<'static>>();
    }
}
