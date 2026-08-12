// RudeAuth C++ SDK — the entire public API.
//
// Design note for anyone auditing this header: there is deliberately no
// function returning a bool that means "is this user licensed". A boolean
// answer is a single byte in memory and a single branch in the disassembly.
// authenticate() returns a Session or an error, and the gating calls exist
// only on a Session — which cannot be constructed without a signature that
// verified against the public key compiled into your binary.
#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

namespace rudeauth {

enum class Error {
    None = 0,
    Network,          // the server could not be reached
    BadResponse,      // malformed, or the envelope did not decode
    SignatureInvalid, // the responder is not who it claims to be
    NonceMismatch,    // a replayed response
    ClockSkew,        // this machine's clock is too far from the server's
    LicenseInvalid,
    // A gated file that does not exist. Kept distinct from LicenseInvalid so a
    // mistyped filename does not read as a licence problem.
    FileNotFound,
    LicenseExpired,
    DeviceLimit,
    DeviceBlacklisted,
    RateLimited,
    SessionExpired,
    EndpointDisabled,
    AppDisabled,
    ResetUnavailable,
    ServerError,
    Internal,
};

const char* to_string(Error e) noexcept;

// Result carries either a value or an error. A failed Result holds no value,
// so there is no way to read one that was never produced.
template <typename T>
class Result {
public:
    static Result success(T v) { return Result(std::move(v)); }
    static Result failure(Error e, std::string msg = {}) {
        Result r;
        r.error_ = e;
        r.message_ = std::move(msg);
        return r;
    }

    // ok() reports whether the CALL succeeded. It never means "the licence is
    // valid" — a rejected licence is ok() == false with a specific Error.
    bool ok() const noexcept { return error_ == Error::None; }
    Error error() const noexcept { return error_; }
    const std::string& message() const noexcept { return message_; }

    T& value() {
        if (!ok()) throw std::runtime_error("rudeauth: value() on a failed Result");
        return value_;
    }
    const T& value() const {
        if (!ok()) throw std::runtime_error("rudeauth: value() on a failed Result");
        return value_;
    }

private:
    Result() = default;
    explicit Result(T v) : value_(std::move(v)) {}

    T value_{};
    Error error_ = Error::None;
    std::string message_;
};

struct LicenseInfo {
    int level = 0;
    std::int64_t expires_at = 0; // unix seconds; 0 means perpetual
    int devices_used = 0;
    int max_devices = 0;
};

class SessionImpl;

// Session is an authenticated, live connection to the server.
//
// It heartbeats on an internal thread from construction. There is no start or
// stop: a session either lives or is destroyed. Destruction zeroizes the
// session key.
class Session {
public:
    ~Session();
    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // variable returns a server-side value. It is fetched fresh; there is no
    // cache and no fallback, because a cached "last known good" value is
    // exactly what an attacker induces by blocking the network.
    Result<std::string> variable(const std::string& key);

    // file returns a decrypted payload that never shipped inside your binary.
    Result<std::vector<std::uint8_t>> file(const std::string& name);

    // webhook asks the server to call one of your configured endpoints, so the
    // URL never appears in your binary.
    Result<std::string> webhook(const std::string& name,
                                const std::map<std::string, std::string>& params);

    const LicenseInfo& info() const noexcept;

    explicit Session(std::unique_ptr<SessionImpl> impl);

private:
    std::unique_ptr<SessionImpl> impl_;
};

class ClientImpl;

class Client {
public:
    // app_id         — the UUID printed by `rudeauth-cli app create`
    // public_key_b64 — the public_key printed by the same command. Safe to
    //                  embed: it verifies responses, it cannot forge them.
    // base_url       — e.g. "https://api.yourproduct.com"
    Client(std::string app_id, std::string public_key_b64, std::string base_url);
    ~Client();
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;

    Result<std::shared_ptr<Session>> authenticate(const std::string& license_key);

    void set_app_version(std::string v);
    void set_timeout_ms(int ms);

private:
    std::unique_ptr<ClientImpl> impl_;
};

// request_device_reset unbinds a licence from its machines so it can be moved.
// The server bounds this by cooldown and lifetime cap; the client cannot.
Result<bool> request_device_reset(const std::string& app_id,
                                  const std::string& public_key_b64,
                                  const std::string& base_url,
                                  const std::string& license_key);

} // namespace rudeauth
