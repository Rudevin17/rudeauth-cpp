#include "crypto.hpp"

#include <cstring>

extern "C" {
#include "vendor/monocypher.h"
#include "vendor/monocypher-ed25519.h"
}

#if defined(_WIN32)
#  include <windows.h>
#  include <bcrypt.h>
#endif

namespace rudeauth::crypto {
namespace {

// ---------------------------------------------------------------- SHA-256 --

constexpr std::uint32_t kK[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

inline std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

struct Sha256 {
    std::uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                          0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    std::uint8_t  buf[64]{};
    std::size_t   buf_len = 0;
    std::uint64_t total   = 0;

    void compress(const std::uint8_t* p) {
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i) {
            w[i] = (std::uint32_t(p[i * 4]) << 24) | (std::uint32_t(p[i * 4 + 1]) << 16) |
                   (std::uint32_t(p[i * 4 + 2]) << 8) | std::uint32_t(p[i * 4 + 3]);
        }
        for (int i = 16; i < 64; ++i) {
            const std::uint32_t s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const std::uint32_t s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        std::uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
        std::uint32_t e = h[4], f = h[5], g = h[6], hh = h[7];

        for (int i = 0; i < 64; ++i) {
            const std::uint32_t S1  = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const std::uint32_t ch  = (e & f) ^ (~e & g);
            const std::uint32_t t1  = hh + S1 + ch + kK[i] + w[i];
            const std::uint32_t S0  = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const std::uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            const std::uint32_t t2  = S0 + maj;
            hh = g; g = f; f = e; e = d + t1;
            d = c; c = b; b = a; a = t1 + t2;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d;
        h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
    }

    void update(const std::uint8_t* data, std::size_t len) {
        total += len;
        while (len > 0) {
            const std::size_t take = (64 - buf_len < len) ? 64 - buf_len : len;
            std::memcpy(buf + buf_len, data, take);
            buf_len += take;
            data += take;
            len -= take;
            if (buf_len == 64) {
                compress(buf);
                buf_len = 0;
            }
        }
    }

    void finish(std::uint8_t out[32]) {
        const std::uint64_t bits = total * 8;
        const std::uint8_t  pad  = 0x80;
        update(&pad, 1);
        const std::uint8_t zero = 0;
        while (buf_len != 56) update(&zero, 1);
        std::uint8_t len_be[8];
        for (int i = 0; i < 8; ++i) len_be[i] = std::uint8_t(bits >> (56 - i * 8));
        update(len_be, 8);
        for (int i = 0; i < 8; ++i) {
            out[i * 4]     = std::uint8_t(h[i] >> 24);
            out[i * 4 + 1] = std::uint8_t(h[i] >> 16);
            out[i * 4 + 2] = std::uint8_t(h[i] >> 8);
            out[i * 4 + 3] = std::uint8_t(h[i]);
        }
    }
};

const char* kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int b64_value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

} // namespace

Bytes sha256(const std::uint8_t* data, std::size_t len) {
    Sha256 s;
    s.update(data, len);
    Bytes out(kSha256Len);
    s.finish(out.data());
    return out;
}

Bytes sha256(const Bytes& data) { return sha256(data.data(), data.size()); }

Bytes hmac_sha256(const Bytes& key, const Bytes& data) {
    std::uint8_t k[64]{};
    if (key.size() > 64) {
        const Bytes hashed = sha256(key);
        std::memcpy(k, hashed.data(), hashed.size());
    } else if (!key.empty()) {
        std::memcpy(k, key.data(), key.size());
    }

    std::uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = std::uint8_t(k[i] ^ 0x36);
        opad[i] = std::uint8_t(k[i] ^ 0x5c);
    }

    Sha256 inner;
    inner.update(ipad, 64);
    inner.update(data.data(), data.size());
    std::uint8_t inner_out[32];
    inner.finish(inner_out);

    Sha256 outer;
    outer.update(opad, 64);
    outer.update(inner_out, 32);
    Bytes out(kSha256Len);
    outer.finish(out.data());

    zeroize(k, sizeof(k));
    zeroize(ipad, sizeof(ipad));
    zeroize(opad, sizeof(opad));
    return out;
}

Bytes hkdf_sha256(const Bytes& secret, const Bytes& salt, const Bytes& info,
                  std::size_t out_len) {
    // Extract.
    const Bytes prk = hmac_sha256(salt, secret);

    // Expand.
    Bytes out;
    Bytes previous;
    std::uint8_t counter = 1;
    while (out.size() < out_len) {
        Bytes input = previous;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(counter++);
        previous = hmac_sha256(prk, input);
        out.insert(out.end(), previous.begin(), previous.end());
    }
    out.resize(out_len);
    return out;
}

bool ed25519_verify(const Bytes& public_key, const Bytes& message, const Bytes& signature) {
    if (public_key.size() != kEd25519Pub || signature.size() != kEd25519Sig) return false;
    // crypto_ed25519_check is the RFC 8032 / SHA-512 variant. Using
    // crypto_eddsa_check here would reject every genuine signature.
    return crypto_ed25519_check(signature.data(), public_key.data(),
                                message.data(), message.size()) == 0;
}

bool verify_envelope(const Bytes& public_key, const std::string& endpoint,
                     const Bytes& data, const Bytes& signature) {
    if (endpoint.empty() || endpoint.find_first_of(": \t\r\n") != std::string::npos) {
        return false;
    }
    const std::string prefix = "rudeauth-v1:" + endpoint + ":";
    const Bytes digest = sha256(data);

    Bytes msg;
    msg.reserve(prefix.size() + digest.size());
    msg.insert(msg.end(), prefix.begin(), prefix.end());
    msg.insert(msg.end(), digest.begin(), digest.end());

    return ed25519_verify(public_key, msg, signature);
}

bool x25519_public(const Bytes& secret_key, Bytes& public_key) {
    if (secret_key.size() != kX25519Len) return false;
    public_key.assign(kX25519Len, 0);
    crypto_x25519_public_key(public_key.data(), secret_key.data());
    return true;
}

bool x25519_keypair(Bytes& public_key, Bytes& secret_key) {
    secret_key = random_bytes(kX25519Len);
    if (secret_key.size() != kX25519Len) return false;
    return x25519_public(secret_key, public_key);
}

bool x25519_shared(const Bytes& secret_key, const Bytes& peer_public, Bytes& shared) {
    if (secret_key.size() != kX25519Len || peer_public.size() != kX25519Len) return false;

    shared.assign(kX25519Len, 0);
    crypto_x25519(shared.data(), secret_key.data(), peer_public.data());

    // A low-order peer key drives the shared secret to all zeroes, which would
    // let an attacker fix the session key to a known value.
    std::uint8_t acc = 0;
    for (const auto b : shared) acc = std::uint8_t(acc | b);
    if (acc == 0) {
        zeroize(shared);
        return false;
    }
    return true;
}

bool derive_session_key(const Bytes& our_secret, const Bytes& their_public,
                        const std::string& session_id, Bytes& key) {
    Bytes shared;
    if (!x25519_shared(our_secret, their_public, shared)) return false;

    static const std::string kSalt = "rudeauth-v1-session";
    const Bytes salt(kSalt.begin(), kSalt.end());
    const Bytes info(session_id.begin(), session_id.end());

    key = hkdf_sha256(shared, salt, info, kSessionKey);
    zeroize(shared);
    return key.size() == kSessionKey;
}

bool xchacha_open(const Bytes& key, const Bytes& blob, const std::string& aad, Bytes& out) {
    if (key.size() != kSessionKey) return false;
    if (blob.size() < kAeadNonce + kAeadMac) return false;

    // Layout produced by the server: nonce || ciphertext || mac
    const std::uint8_t* nonce  = blob.data();
    const std::size_t   ct_len = blob.size() - kAeadNonce - kAeadMac;
    const std::uint8_t* ct     = blob.data() + kAeadNonce;
    const std::uint8_t* mac    = blob.data() + kAeadNonce + ct_len;

    out.assign(ct_len, 0);
    const int rc = crypto_aead_unlock(
        out.data(), mac, key.data(), nonce,
        reinterpret_cast<const std::uint8_t*>(aad.data()), aad.size(), ct, ct_len);

    if (rc != 0) {
        zeroize(out);
        out.clear();
        return false;
    }
    return true;
}

bool random_bytes(std::uint8_t* buf, std::size_t len) {
#if defined(_WIN32)
    return BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    (void)buf; (void)len;
    return false;
#endif
}

Bytes random_bytes(std::size_t len) {
    Bytes b(len);
    if (!random_bytes(b.data(), len)) b.clear();
    return b;
}

void zeroize(void* p, std::size_t len) {
#if defined(_WIN32)
    SecureZeroMemory(p, len);
#else
    volatile auto* v = static_cast<volatile unsigned char*>(p);
    while (len--) *v++ = 0;
#endif
}

void zeroize(Bytes& b) {
    if (!b.empty()) zeroize(b.data(), b.size());
}

std::string base64_encode(const Bytes& in) {
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);

    std::size_t i = 0;
    for (; i + 2 < in.size(); i += 3) {
        const std::uint32_t n = (std::uint32_t(in[i]) << 16) |
                                (std::uint32_t(in[i + 1]) << 8) | in[i + 2];
        out += kB64[(n >> 18) & 63];
        out += kB64[(n >> 12) & 63];
        out += kB64[(n >> 6) & 63];
        out += kB64[n & 63];
    }
    if (i + 1 == in.size()) {
        const std::uint32_t n = std::uint32_t(in[i]) << 16;
        out += kB64[(n >> 18) & 63];
        out += kB64[(n >> 12) & 63];
        out += "==";
    } else if (i + 2 == in.size()) {
        const std::uint32_t n = (std::uint32_t(in[i]) << 16) | (std::uint32_t(in[i + 1]) << 8);
        out += kB64[(n >> 18) & 63];
        out += kB64[(n >> 12) & 63];
        out += kB64[(n >> 6) & 63];
        out += '=';
    }
    return out;
}

bool base64_decode(const std::string& in, Bytes& out) {
    out.clear();
    out.reserve((in.size() / 4) * 3);

    std::uint32_t acc = 0;
    int bits = 0;
    for (const char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        const int v = b64_value(c);
        if (v < 0) return false;
        acc = (acc << 6) | std::uint32_t(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(std::uint8_t((acc >> bits) & 0xFF));
        }
    }
    return true;
}

std::string hex_encode(const Bytes& in) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.reserve(in.size() * 2);
    for (const auto b : in) {
        out += d[b >> 4];
        out += d[b & 15];
    }
    return out;
}

bool hex_decode(const std::string& in, Bytes& out) {
    if (in.size() % 2 != 0) return false;
    out.clear();
    out.reserve(in.size() / 2);

    auto nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    for (std::size_t i = 0; i < in.size(); i += 2) {
        const int hi = nibble(in[i]), lo = nibble(in[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(std::uint8_t((hi << 4) | lo));
    }
    return true;
}

} // namespace rudeauth::crypto
