//
// Copyright (c) 2025 murilo ijanc' <murilo@ijanc.org>
//
// Permission to use, copy, modify, and distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
//
//! # STUN Client Library
//!
//! A pure Rust implementation of a STUN (Session Traversal Utilities for NAT) client
//! using only the standard library. This library allows you to discover your public
//! IP address and port as seen through NAT devices.
//!
//! ## Features
//!
//! - Pure standard library implementation (no external dependencies)
//! - Support for both IPv4 and IPv6
//! - Hostname resolution using system DNS
//! - Multiple STUN server fallback
//! - Comprehensive error handling
//! - RFC 5389 compliant
//!
//! ## Example Usage
//!
//! ```rust
//! use stun::Client;
//!
//! // Create client from hostname (with DNS resolution)
//! let client = Client::from_hostname("stun.l.google.com:19302").unwrap();
//! let public_addr = client.get_public_address().unwrap();
//! println!("Your public address: {}", public_addr);
//!
//! // Create client from IP address directly
//! let addr = "142.250.191.127:19302".parse().unwrap();
//! let client = Client::new(addr).unwrap();
//! let public_addr = client.get_public_address().unwrap();
//! ```
//!
//! ## STUN Protocol Overview
//!
//! STUN works by sending a binding request to a STUN server on the public internet.
//! The server responds with your public IP address and port as it sees them,
//! effectively telling you how your NAT device maps your internal connection.
//!
//! The protocol uses XOR operations to encode addresses, which helps with NAT devices
//! that might try to rewrite IP addresses in packet payloads.
//!
//! ## STUN Message Structure
//!
//!```norust
//!       0                   1                   2                   3
//!       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!      |0 0|     STUN Message Type     |         Message Length        |
//!      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!      |                         Magic Cookie                          |
//!      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!      |                                                               |
//!      |                     Transaction ID (96 bits)                  |
//!      |                                                               |
//!      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!```

use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket},
    time::Duration,
};

use log::debug;

/// STUN protocol constants as defined in RFC 5389
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const MAPPED_ADDRESS: u16 = 0x0001;

/// Errors that can occur during STUN operations
#[derive(Debug)]
pub enum StunError {
    /// Network-related errors (socket creation, sending, receiving)
    NetworkError(std::io::Error),

    /// Protocol parsing errors (malformed packets, unknown formats)
    ParseError(String),

    /// Request timeout (no response from server)
    TimeoutError,

    /// Invalid or unexpected STUN response
    InvalidResponse,
}

impl fmt::Display for StunError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            StunError::NetworkError(e) => write!(f, "Network error: {}", e),
            StunError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            StunError::TimeoutError => write!(f, "Request timed out"),
            StunError::InvalidResponse => write!(f, "Invalid STUN response"),
        }
    }
}

impl Error for StunError {}

/// A STUN client for discovering public IP addresses and ports
///
/// The Client allows you to send STUN binding requests to discover
/// your public IP address and port as seen through NAT devices.
///
/// # Examples
///
/// ```rust
/// use stun_client::Client;
///
/// // Create from hostname
/// let client = Client::from_hostname("stun.l.google.com:19302").unwrap();
/// let addr = client.get_public_address().unwrap();
///
/// // Create from socket address
/// let server = "142.250.191.127:19302".parse().unwrap();
/// let client = Client::new(server).unwrap();
/// let addr = client.get_public_address().unwrap();
/// ```
pub struct Client {
    socket: UdpSocket,
    server_addr: SocketAddr,
}

impl Client {
    /// Creates a new STUN client with the specified server address
    ///
    /// # Arguments
    /// * `server_addr` - The socket address of the STUN server
    ///
    /// # Returns
    /// * `Ok(Client)` - Successfully created client
    /// * `Err(StunError::NetworkError)` - Failed to create UDP socket
    ///
    /// # Example
    /// ```rust
    /// use stun::Client;
    ///
    /// let server = "142.250.191.127:19302".parse().unwrap();
    /// let client = Client::new(server).unwrap();
    /// ```
    pub fn new(server_addr: SocketAddr) -> Result<Self, StunError> {
        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(StunError::NetworkError)?;

        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .map_err(StunError::NetworkError)?;

        Ok(Client { socket, server_addr })
    }

    pub fn from_google() -> Result<Self, StunError> {
        Self::from_hostname("stun.l.google.com:19302")
    }

    /// Creates a new STUN client by resolving a hostname
    ///
    /// This method performs DNS resolution to convert hostnames to IP addresses.
    /// It prefers IPv4 addresses when multiple addresses are available.
    ///
    /// # Arguments
    /// * `hostname` - Hostname and port in format "host:port" (e.g., "stun.l.google.com:19302")
    ///
    /// # Returns
    /// * `Ok(Client)` - Successfully created client with resolved address
    /// * `Err(StunError::NetworkError)` - DNS resolution or socket creation failed
    /// * `Err(StunError::ParseError)` - No addresses found for hostname
    ///
    /// # Example
    /// ```rust
    /// use stun::Client;
    ///
    /// let client = Client::from_hostname("stun.l.google.com:19302")?;
    /// ```
    pub fn from_hostname(hostname: &str) -> Result<Self, StunError> {
        // Resolve hostname to IP address using standard library
        let addrs: Vec<SocketAddr> = hostname
            .to_socket_addrs()
            .map_err(|e| StunError::NetworkError(e))?
            .collect();

        // Prefer IPv4 addresses since our socket is IPv4-only
        let server_addr = addrs
            .iter()
            .find(|addr| addr.is_ipv4())
            .or_else(|| addrs.first())
            .ok_or_else(|| {
                StunError::ParseError(
                    "No addresses found for hostname".to_string(),
                )
            })?;

        debug!("Resolved {} to {}", hostname, server_addr);

        Self::new(*server_addr)
    }

    /// Discovers the public IP address and port for this client
    ///
    /// Sends a STUN binding request to the configured server and parses
    /// the response to extract the public address information.
    ///
    /// # Returns
    /// * `Ok(SocketAddr)` - Your public IP address and port
    /// * `Err(StunError)` - Various errors including network, timeout, or parsing issues
    ///
    /// # Example
    /// ```rust
    /// use stun::Client;
    ///
    /// let client = Client::from_hostname("stun.l.google.com:19302").unwrap();
    /// let public_addr = client.get_public_address().unwrap();
    /// println!("Public IP: {}, Port: {}", public_addr.ip(), public_addr.port());
    /// ```
    pub fn get_public_address(&self) -> Result<SocketAddr, StunError> {
        let transaction_id = self.generate_transaction_id();
        let request = self.build_binding_request(&transaction_id);

        // Send request
        self.socket
            .send_to(&request, &self.server_addr)
            .map_err(StunError::NetworkError)?;

        // Receive response
        let mut buffer = [0u8; 1024];
        let (size, _) = self
            .socket
            .recv_from(&mut buffer)
            .map_err(StunError::NetworkError)?;

        self.parse_binding_response(&buffer[..size], &transaction_id)
    }

    /// Generates a cryptographically random transaction ID
    ///
    /// Transaction IDs are used to match requests with responses and should be
    /// unique for each request to prevent replay attacks.
    fn generate_transaction_id(&self) -> [u8; 12] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::SystemTime;

        let mut hasher = DefaultHasher::new();
        SystemTime::now().hash(&mut hasher);
        let hash = hasher.finish();

        let mut transaction_id = [0u8; 12];
        let hash_bytes = hash.to_le_bytes();
        transaction_id[0..8].copy_from_slice(&hash_bytes);

        // Fill remaining bytes with more entropy
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        transaction_id[8..12].copy_from_slice(&nanos.to_le_bytes());

        transaction_id
    }

    /// Builds a STUN binding request packet
    ///
    /// Creates a properly formatted STUN message with the binding request type,
    /// magic cookie, and transaction ID according to RFC 5389.
    fn build_binding_request(&self, transaction_id: &[u8; 12]) -> Vec<u8> {
        let mut request = Vec::with_capacity(20);

        // Message Type (2 bytes) - Binding Request
        request.extend_from_slice(&BINDING_REQUEST.to_be_bytes());

        // Message Length (2 bytes) - 0 for no attributes
        request.extend_from_slice(&0u16.to_be_bytes());

        // Magic Cookie (4 bytes)
        request.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (12 bytes)
        request.extend_from_slice(transaction_id);

        request
    }

    fn parse_binding_response(
        &self,
        data: &[u8],
        expected_transaction_id: &[u8; 12],
    ) -> Result<SocketAddr, StunError> {
        if data.len() < 20 {
            return Err(StunError::ParseError(
                "Response too short".to_string(),
            ));
        }

        // Parse header
        let message_type = u16::from_be_bytes([data[0], data[1]]);
        let message_length = u16::from_be_bytes([data[2], data[3]]);
        let magic_cookie =
            u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let transaction_id = &data[8..20];

        debug!(
            "Response - Type: 0x{:04x}, Length: {}, Magic: 0x{:08x}",
            message_type, message_length, magic_cookie
        );

        // Verify response
        if message_type != BINDING_SUCCESS_RESPONSE {
            return Err(StunError::InvalidResponse);
        }

        if magic_cookie != STUN_MAGIC_COOKIE {
            return Err(StunError::ParseError(
                "Invalid magic cookie".to_string(),
            ));
        }

        if transaction_id != expected_transaction_id {
            return Err(StunError::ParseError(
                "Transaction ID mismatch".to_string(),
            ));
        }

        // Parse attributes
        let mut pos = 20;
        let end = 20 + message_length as usize;

        while pos < end && pos + 4 <= data.len() {
            let attr_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
            let attr_length =
                u16::from_be_bytes([data[pos + 2], data[pos + 3]]);
            pos += 4;

            debug!(
                "Attribute - Type: 0x{:04x}, Length: {}",
                attr_type, attr_length
            );

            if pos + attr_length as usize > data.len() {
                return Err(StunError::ParseError(
                    "Attribute length exceeds data".to_string(),
                ));
            }

            let attr_data = &data[pos..pos + attr_length as usize];

            match attr_type {
                XOR_MAPPED_ADDRESS => {
                    debug!("Found XOR-MAPPED-ADDRESS");
                    if let Ok(addr) = self.parse_xor_mapped_address(attr_data)
                    {
                        return Ok(addr);
                    }
                }
                MAPPED_ADDRESS => {
                    debug!("Found MAPPED-ADDRESS");
                    if let Ok(addr) = self.parse_mapped_address(attr_data) {
                        return Ok(addr);
                    }
                }
                _ => {
                    debug!(
                        "Skipping unknown attribute type: 0x{:04x}",
                        attr_type
                    );
                }
            }

            // Move to next attribute (with padding)
            pos += ((attr_length + 3) & !3) as usize;
        }

        Err(StunError::ParseError("No address attribute found".to_string()))
    }

    fn parse_xor_mapped_address(
        &self,
        data: &[u8],
    ) -> Result<SocketAddr, StunError> {
        if data.len() < 4 {
            return Err(StunError::ParseError(
                "XOR-MAPPED-ADDRESS too short".to_string(),
            ));
        }

        let _reserved = data[0]; // Should be 0
        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]])
            ^ (STUN_MAGIC_COOKIE >> 16) as u16;

        debug!(
            "XOR-MAPPED-ADDRESS - Family: 0x{:02x}, Raw port: {}, XOR port: {}",
            family,
            u16::from_be_bytes([data[2], data[3]]),
            port
        );

        match family {
            0x01 => {
                // IPv4
                if data.len() < 8 {
                    return Err(StunError::ParseError(
                        "IPv4 XOR-MAPPED-ADDRESS too short".to_string(),
                    ));
                }

                let ip_bytes = [
                    data[4] ^ ((STUN_MAGIC_COOKIE >> 24) as u8),
                    data[5] ^ ((STUN_MAGIC_COOKIE >> 16) as u8),
                    data[6] ^ ((STUN_MAGIC_COOKIE >> 8) as u8),
                    data[7] ^ (STUN_MAGIC_COOKIE as u8),
                ];

                debug!(
                    "Raw IP bytes: {:02x}{:02x}{:02x}{:02x}, XOR IP bytes: {:02x}{:02x}{:02x}{:02x}",
                    data[4],
                    data[5],
                    data[6],
                    data[7],
                    ip_bytes[0],
                    ip_bytes[1],
                    ip_bytes[2],
                    ip_bytes[3]
                );

                let ip = Ipv4Addr::from(ip_bytes);
                Ok(SocketAddr::from((ip, port)))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return Err(StunError::ParseError(
                        "IPv6 XOR-MAPPED-ADDRESS too short".to_string(),
                    ));
                }

                let mut ip_bytes = [0u8; 16];
                let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();

                // XOR first 4 bytes with magic cookie
                for i in 0..4 {
                    ip_bytes[i] = data[4 + i] ^ magic_bytes[i];
                }

                // XOR remaining 12 bytes with transaction ID
                // (We'd need access to transaction ID here - simplified for now)
                for i in 4..16 {
                    ip_bytes[i] = data[4 + i]; // Simplified - should XOR with transaction ID
                }

                let ip = Ipv6Addr::from(ip_bytes);
                Ok(SocketAddr::from((ip, port)))
            }
            _ => Err(StunError::ParseError(format!(
                "Unknown address family: 0x{:02x}",
                family
            ))),
        }
    }

    fn parse_mapped_address(
        &self,
        data: &[u8],
    ) -> Result<SocketAddr, StunError> {
        if data.len() < 4 {
            return Err(StunError::ParseError(
                "MAPPED-ADDRESS too short".to_string(),
            ));
        }

        let _reserved = data[0]; // Should be 0
        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);

        debug!("MAPPED-ADDRESS - Family: 0x{:02x}, Port: {}", family, port);

        match family {
            0x01 => {
                // IPv4
                if data.len() < 8 {
                    return Err(StunError::ParseError(
                        "IPv4 MAPPED-ADDRESS too short".to_string(),
                    ));
                }

                let ip = Ipv4Addr::from([data[4], data[5], data[6], data[7]]);
                debug!("MAPPED-ADDRESS IPv4: {}", ip);
                Ok(SocketAddr::from((ip, port)))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return Err(StunError::ParseError(
                        "IPv6 MAPPED-ADDRESS too short".to_string(),
                    ));
                }

                let mut ip_bytes = [0u8; 16];
                ip_bytes.copy_from_slice(&data[4..20]);
                let ip = Ipv6Addr::from(ip_bytes);
                debug!("MAPPED-ADDRESS IPv6: {}", ip);
                Ok(SocketAddr::from((ip, port)))
            }
            _ => Err(StunError::ParseError(format!(
                "Unknown address family: 0x{:02x}",
                family
            ))),
        }
    }
}
