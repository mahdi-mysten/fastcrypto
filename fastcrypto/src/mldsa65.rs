// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

//! This module contains an implementation of the [ML-DSA-65](https://csrc.nist.gov/pubs/fips/204/final) (FIPS 204) signature scheme.
//!
//! The module is gated behind the `mldsa65` feature.
//!
//! The private key is the 32-byte seed \zeta from FIPS 204 key generation. The expanded private
//! key is an internal cache derived from it and is never serialized.

/// The length of a private key in bytes: the FIPS 204 seed \zeta.
pub const MLDSA65_PRIVATE_KEY_LENGTH: usize = 32;

/// The length of a public key in bytes.
pub const MLDSA65_PUBLIC_KEY_LENGTH: usize = 1952;

/// The length of a signature in bytes.
pub const MLDSA65_SIGNATURE_LENGTH: usize = 3309;

/// The key pair bytes length is the same as the private key length.
/// This enforces deserialization to always derive the public key from the private key.
pub const MLDSA65_KEYPAIR_LENGTH: usize = MLDSA65_PRIVATE_KEY_LENGTH;
