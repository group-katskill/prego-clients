//! Keys and signatures on this computer: public JWKs and thumbprints, local private key files, and JWS for
//! Prego signed sets and A2A card signatures (ADR-0061 sections 3 and 6, ADR-0062 section 5). Written from
//! the RFCs, the A2A 1.0 specification and the ADR text, with ring for the cryptography.

pub mod der;
pub mod jwk;
pub mod jws;
pub mod keyfile;
#[cfg(test)]
pub mod scrub_dir;
