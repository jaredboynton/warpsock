//! HTTP transport implementations.
//!
//! - HTTP/1.1 via httparse + tokio-boring (minimal, no hyper)
//! - HTTP/2 via custom implementation (full fingerprint control)
//! - HTTP/3 via quiche

pub mod connector;
pub mod dns;
pub mod h1;
pub mod h1_h2;
pub mod h2;
pub mod h3;
pub mod session;
pub mod tcp;
