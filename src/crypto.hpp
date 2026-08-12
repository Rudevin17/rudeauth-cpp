// RudeAuth SDK — cryptographic primitives.
//
// SHA-256, HMAC-SHA256 and HKDF-SHA256 are implemented here directly. X25519,
// XChaCha20-Poly1305 and Ed25519 verification wrap Monocypher.
//
// IMPORTANT: Ed25519 verification MUST use monocypher-ed25519.h
// (crypto_ed25519_check), which is RFC 8032 / SHA-512 based. Monocypher's
// default crypto_eddsa_check is BLAKE2b based and rejects every signature the
// Go server produces. crypto_test.cpp exists primarily to catch that.
#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

namespace rudeauth::crypto {

using Bytes = std::vector<std::uint8_t>;

inline constexpr std::size_t kSha256Len   = 32;
inline constexpr std::size_t kX25519Len   = 32;
inline constexpr std::size_t kSessionKey  = 32;
inline constexpr std::size_t kEd25519Pub  = 32;
inline constexpr std::size_t kEd25519Sig  = 64;
inline constexpr std::size_t kAeadNonce   = 24;
inline constexpr std::size_t kAeadMac     = 16;

Bytes sha256(const std::uint8_t* data, std::size_t len);
Bytes sha256(const Bytes& data);

Bytes hmac_sha256(const Bytes& key, const Bytes& data);

// hkdf_sha256 performs extract-then-expand, matching Go's
// hkdf.New(sha256.New, secret, salt, info).
Bytes hkdf_sha256(const Bytes& secret, const Bytes& salt, const Bytes& info,
                  std::size_t out_len);

// ed25519_verify checks a signature over the exact message bytes given.
bool ed25519_verify(const Bytes& public_key, const Bytes& message, const Bytes& signature);

// verify_envelope checks a RudeAuth response signature: the signed message is
// "rudeauth-v1:<endpoint>:" || sha256(data). The caller passes the raw bytes
// received off the wire, BEFORE parsing them.
bool verify_envelope(const Bytes& public_key, const std::string& endpoint,
                     const Bytes& data, const Bytes& signature);

// x25519_keypair generates an ephemeral pair for one handshake.
bool x25519_keypair(Bytes& public_key, Bytes& secret_key);

// x25519_public derives the public half of a known secret. Used by tests.
bool x25519_public(const Bytes& secret_key, Bytes& public_key);

// x25519_shared performs the exchange. Returns false for a low-order peer key,
// which would otherwise fix the shared secret to a known value.
bool x25519_shared(const Bytes& secret_key, const Bytes& peer_public, Bytes& shared);

// derive_session_key reproduces the server's derivation exactly: X25519 then
// HKDF-SHA256 with the fixed protocol salt and the session ID as info.
bool derive_session_key(const Bytes& our_secret, const Bytes& their_public,
                        const std::string& session_id, Bytes& key);

// xchacha_open opens a blob laid out as nonce(24) || ciphertext || mac(16),
// which is what the server's SealForSession produces.
bool xchacha_open(const Bytes& key, const Bytes& blob, const std::string& aad, Bytes& out);

// random_bytes fills buf from the system CSPRNG.
bool random_bytes(std::uint8_t* buf, std::size_t len);
Bytes random_bytes(std::size_t len);

// zeroize erases secrets in a way the optimiser may not remove.
void zeroize(void* p, std::size_t len);
void zeroize(Bytes& b);

// Encoding helpers used across the SDK.
std::string base64_encode(const Bytes& in);
bool        base64_decode(const std::string& in, Bytes& out);
std::string hex_encode(const Bytes& in);
bool        hex_decode(const std::string& in, Bytes& out);

} // namespace rudeauth::crypto
