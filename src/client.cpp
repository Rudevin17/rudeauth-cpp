#include "rudeauth/rudeauth.hpp"

#include "crypto.hpp"
#include "fingerprint.hpp"
#include "http.hpp"
#include "json.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <sstream>
#include <thread>

namespace rudeauth {
namespace {

using crypto::Bytes;

constexpr std::size_t kMaxResponse = 32u * 1024u * 1024u; // encrypted files can be large
constexpr int         kDefaultTimeoutMs = 15000;
constexpr std::int64_t kMaxClockSkewSec = 300;

// map_wire_error turns the server's coarse vocabulary into an Error. Unknown
// codes become ServerError rather than being ignored: a code this SDK does not
// recognise is a reason to stop, not to continue.
Error map_wire_error(const std::string& code) {
    if (code == "LICENSE_INVALID")     return Error::LicenseInvalid;
    if (code == "LICENSE_EXPIRED")     return Error::LicenseExpired;
    if (code == "DEVICE_LIMIT")        return Error::DeviceLimit;
    if (code == "DEVICE_BLACKLISTED")  return Error::DeviceBlacklisted;
    if (code == "RATE_LIMITED")        return Error::RateLimited;
    if (code == "SESSION_EXPIRED")     return Error::SessionExpired;
    if (code == "ENDPOINT_DISABLED")   return Error::EndpointDisabled;
    if (code == "APP_DISABLED")        return Error::AppDisabled;
    if (code == "CLOCK_SKEW")          return Error::ClockSkew;
    if (code == "RESET_UNAVAILABLE")   return Error::ResetUnavailable;
    if (code == "FILE_NOT_FOUND")      return Error::FileNotFound;
    if (code == "SERVER_ERROR")        return Error::ServerError;
    return Error::ServerError;
}

std::int64_t now_unix() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

// Transport shared by every call. Returns the VERIFIED payload bytes, or an
// error. There is no path through this function that yields unverified data.
struct Verified {
    bool        ok = false;
    Error       error = Error::None;
    std::string message;
    json::Value payload;
};

Verified call_endpoint(const std::string& base_url, const std::string& path,
                       const std::string& endpoint, const Bytes& public_key,
                       const std::string& request_body, int timeout_ms) {
    Verified v;

    const auto resp = http::post(base_url + path, request_body, timeout_ms, kMaxResponse);
    if (!resp.transport_ok) {
        v.error = Error::Network;
        v.message = resp.error;
        return v;
    }
    if (resp.status != 200) {
        // A non-200 carries no signed envelope, so nothing about it can be
        // trusted beyond "this was not a normal answer".
        v.error = Error::BadResponse;
        v.message = "http status " + std::to_string(resp.status);
        return v;
    }

    json::Value envelope;
    if (!json::parse(resp.body, envelope) || envelope.type != json::Value::Type::Object) {
        v.error = Error::BadResponse;
        v.message = "envelope did not parse";
        return v;
    }

    Bytes data, signature;
    if (!crypto::base64_decode(envelope.str("data"), data) ||
        !crypto::base64_decode(envelope.str("signature"), signature) ||
        data.empty() || signature.empty()) {
        v.error = Error::BadResponse;
        v.message = "envelope fields missing or not base64";
        return v;
    }

    // STEP ONE, before anything is parsed: the bytes must be signed by the key
    // compiled into this binary. Everything downstream depends on this and
    // there is no flag to skip it.
    if (!crypto::verify_envelope(public_key, endpoint, data, signature)) {
        v.error = Error::SignatureInvalid;
        v.message = "response was not signed by this application's key";
        return v;
    }

    const std::string payload_text(data.begin(), data.end());
    if (!json::parse(payload_text, v.payload) ||
        v.payload.type != json::Value::Type::Object) {
        v.error = Error::BadResponse;
        v.message = "payload did not parse";
        return v;
    }

    v.ok = true;
    return v;
}

std::string json_string_array(const std::vector<std::string>& items) {
    std::ostringstream o;
    o << '[';
    for (std::size_t i = 0; i < items.size(); ++i) {
        if (i) o << ',';
        o << '"' << json::escape(items[i]) << '"';
    }
    o << ']';
    return o.str();
}

} // namespace

const char* to_string(Error e) noexcept {
    switch (e) {
        case Error::None:              return "none";
        case Error::Network:           return "network unreachable";
        case Error::BadResponse:       return "malformed response";
        case Error::SignatureInvalid:  return "signature invalid — the server is not authentic";
        case Error::NonceMismatch:     return "nonce mismatch — replayed response";
        case Error::ClockSkew:         return "system clock is too far from the server's";
        case Error::LicenseInvalid:    return "licence invalid";
        case Error::FileNotFound:      return "no such file for this application";
        case Error::LicenseExpired:    return "licence expired";
        case Error::DeviceLimit:       return "device limit reached";
        case Error::DeviceBlacklisted: return "device blacklisted";
        case Error::RateLimited:       return "rate limited";
        case Error::SessionExpired:    return "session expired";
        case Error::EndpointDisabled:  return "endpoint disabled";
        case Error::AppDisabled:       return "application unavailable";
        case Error::ResetUnavailable:  return "device reset unavailable";
        case Error::ServerError:       return "server error";
        case Error::Internal:          return "internal error";
    }
    return "unknown";
}

// --------------------------------------------------------------- Session ---

class SessionImpl {
public:
    SessionImpl(std::string app_id, Bytes public_key, std::string base_url,
                std::string token_b64, Bytes session_key, LicenseInfo info,
                std::int64_t expires_at, int timeout_ms)
        : app_id_(std::move(app_id)),
          public_key_(std::move(public_key)),
          base_url_(std::move(base_url)),
          token_b64_(std::move(token_b64)),
          session_key_(std::move(session_key)),
          info_(info),
          expires_at_(expires_at),
          timeout_ms_(timeout_ms) {
        beat_thread_ = std::thread([this] { beat_loop(); });
    }

    ~SessionImpl() {
        {
            std::lock_guard<std::mutex> lock(mu_);
            stop_ = true;
        }
        cv_.notify_all();
        if (beat_thread_.joinable()) beat_thread_.join();

        crypto::zeroize(session_key_);
        crypto::zeroize(reinterpret_cast<void*>(token_b64_.data()), token_b64_.size());
    }

    const LicenseInfo& info() const noexcept { return info_; }

    // sealed_call performs a gating request and opens the returned payload.
    Result<Bytes> sealed_call(const std::string& path, const std::string& endpoint,
                              const std::string& body, const std::string& aad) {
        const auto v = call_endpoint(base_url_, path, endpoint, public_key_, body, timeout_ms_);
        if (!v.ok) return Result<Bytes>::failure(v.error, v.message);

        if (!v.payload.boolean_at("success")) {
            return Result<Bytes>::failure(map_wire_error(v.payload.str("error")),
                                          v.payload.str("error"));
        }

        Bytes sealed;
        if (!crypto::base64_decode(v.payload.str("sealed"), sealed)) {
            return Result<Bytes>::failure(Error::BadResponse, "sealed field is not base64");
        }

        Bytes out;
        std::lock_guard<std::mutex> lock(mu_);
        if (!crypto::xchacha_open(session_key_, sealed, aad, out)) {
            return Result<Bytes>::failure(Error::BadResponse,
                                          "sealed payload did not open for this session");
        }
        return Result<Bytes>::success(std::move(out));
    }

    std::string app_id() const { return app_id_; }
    std::string token() const { return token_b64_; }
    std::string base_url() const { return base_url_; }
    int timeout_ms() const { return timeout_ms_; }
    const Bytes& public_key() const { return public_key_; }

private:
    // beat_loop keeps the session alive.
    //
    // A missed beat is NOT a logout: network blips are constant, and dropping
    // a paying customer over a three-second hiccup is a self-inflicted support
    // ticket. Failures simply retry until the TTL genuinely lapses.
    void beat_loop() {
        for (;;) {
            std::int64_t ttl_remaining;
            {
                std::lock_guard<std::mutex> lock(mu_);
                ttl_remaining = expires_at_ - now_unix();
            }
            auto wait = std::chrono::seconds(ttl_remaining > 4 ? ttl_remaining / 2 : 2);

            std::unique_lock<std::mutex> lock(mu_);
            if (cv_.wait_for(lock, wait, [this] { return stop_; })) return;
            lock.unlock();

            beat_once();
        }
    }

    void beat_once() {
        std::ostringstream body;
        body << R"({"app_id":")" << json::escape(app_id_)
             << R"(","session_token":")" << json::escape(token_b64_) << R"("})";

        const auto v = call_endpoint(base_url_, "/v1/heartbeat", "heartbeat",
                                     public_key_, body.str(), timeout_ms_);
        if (!v.ok) return; // transient; the TTL still governs

        if (!v.payload.boolean_at("valid")) return; // let the TTL lapse naturally

        const auto expires = v.payload.num("expires_at");
        if (expires > 0) {
            std::lock_guard<std::mutex> lock(mu_);
            expires_at_ = expires;
        }
    }

    std::string app_id_;
    Bytes       public_key_;
    std::string base_url_;
    std::string token_b64_;
    Bytes       session_key_;
    LicenseInfo info_;
    std::int64_t expires_at_ = 0;
    int         timeout_ms_ = kDefaultTimeoutMs;

    std::thread             beat_thread_;
    std::mutex              mu_;
    std::condition_variable cv_;
    bool                    stop_ = false;
};

Session::Session(std::unique_ptr<SessionImpl> impl) : impl_(std::move(impl)) {}
Session::~Session() = default;

const LicenseInfo& Session::info() const noexcept { return impl_->info(); }

Result<std::string> Session::variable(const std::string& key) {
    std::ostringstream body;
    body << R"({"app_id":")" << json::escape(impl_->app_id())
         << R"(","session_token":")" << json::escape(impl_->token()) << R"("})";

    auto r = impl_->sealed_call("/v1/variables", "variables", body.str(), "variables");
    if (!r.ok()) return Result<std::string>::failure(r.error(), r.message());

    const std::string text(r.value().begin(), r.value().end());
    json::Value vars;
    if (!json::parse(text, vars) || vars.type != json::Value::Type::Object) {
        return Result<std::string>::failure(Error::BadResponse, "variables did not parse");
    }
    const auto* v = vars.find(key);
    if (!v || v->type != json::Value::Type::String) {
        return Result<std::string>::failure(Error::BadResponse, "no such variable: " + key);
    }
    return Result<std::string>::success(v->string);
}

Result<std::vector<std::uint8_t>> Session::file(const std::string& name) {
    std::ostringstream body;
    body << R"({"app_id":")" << json::escape(impl_->app_id())
         << R"(","session_token":")" << json::escape(impl_->token())
         << R"(","name":")" << json::escape(name) << R"("})";

    return impl_->sealed_call("/v1/files", "files", body.str(), "files:" + name);
}

Result<std::string> Session::webhook(const std::string& name,
                                     const std::map<std::string, std::string>& params) {
    std::ostringstream body;
    body << R"({"app_id":")" << json::escape(impl_->app_id())
         << R"(","session_token":")" << json::escape(impl_->token())
         << R"(","name":")" << json::escape(name) << R"(","params":{)";
    bool first = true;
    for (const auto& [k, val] : params) {
        if (!first) body << ',';
        first = false;
        body << '"' << json::escape(k) << "\":\"" << json::escape(val) << '"';
    }
    body << "}}";

    const auto v = call_endpoint(impl_->base_url(), "/v1/webhook", "webhook",
                                 impl_->public_key(), body.str(), impl_->timeout_ms());
    if (!v.ok) return Result<std::string>::failure(v.error, v.message);
    if (!v.payload.boolean_at("success")) {
        return Result<std::string>::failure(map_wire_error(v.payload.str("error")),
                                            v.payload.str("error"));
    }

    Bytes decoded;
    crypto::base64_decode(v.payload.str("body"), decoded);
    return Result<std::string>::success(std::string(decoded.begin(), decoded.end()));
}

// ---------------------------------------------------------------- Client ---

class ClientImpl {
public:
    std::string app_id;
    Bytes       public_key;
    std::string base_url;
    std::string app_version = "1.0.0";
    int         timeout_ms  = kDefaultTimeoutMs;
};

Client::Client(std::string app_id, std::string public_key_b64, std::string base_url)
    : impl_(std::make_unique<ClientImpl>()) {
    impl_->app_id = std::move(app_id);
    crypto::base64_decode(public_key_b64, impl_->public_key);

    // Tolerate a trailing slash so both forms of base URL work.
    if (!base_url.empty() && base_url.back() == '/') base_url.pop_back();
    impl_->base_url = std::move(base_url);
}

Client::~Client() = default;

void Client::set_app_version(std::string v) { impl_->app_version = std::move(v); }
void Client::set_timeout_ms(int ms)         { impl_->timeout_ms = ms; }

Result<std::shared_ptr<Session>> Client::authenticate(const std::string& license_key) {
    using R = Result<std::shared_ptr<Session>>;

    if (impl_->public_key.size() != crypto::kEd25519Pub) {
        return R::failure(Error::Internal, "public key is not 32 bytes");
    }

    const auto components = fingerprint::collect();
    if (components.size() < fingerprint::kMinComponents) {
        // Refusing beats sending a weak identity the server would have to
        // accept: one component is trivially forged and leaves no drift
        // tolerance.
        return R::failure(Error::Internal, "could not read enough hardware components");
    }

    Bytes eph_pub, eph_secret;
    if (!crypto::x25519_keypair(eph_pub, eph_secret)) {
        return R::failure(Error::Internal, "ephemeral key generation failed");
    }
    const Bytes nonce = crypto::random_bytes(32);
    if (nonce.size() != 32) return R::failure(Error::Internal, "rng unavailable");

    const std::string nonce_b64 = crypto::base64_encode(nonce);

    std::ostringstream body;
    body << R"({"app_id":")" << json::escape(impl_->app_id)
         << R"(","app_version":")" << json::escape(impl_->app_version)
         << R"(","license_key":")" << json::escape(license_key)
         << R"(","fingerprint_components":)" << json_string_array(components)
         << R"(,"fingerprint_label":")" << json::escape(fingerprint::label())
         << R"(","client_nonce":")" << nonce_b64
         << R"(","eph_pubkey":")" << crypto::base64_encode(eph_pub)
         << R"(","sent_at":)" << now_unix() << "}";

    const auto v = call_endpoint(impl_->base_url, "/v1/handshake", "handshake",
                                 impl_->public_key, body.str(), impl_->timeout_ms);
    if (!v.ok) {
        crypto::zeroize(const_cast<Bytes&>(eph_secret));
        return R::failure(v.error, v.message);
    }

    // The echoed nonce proves this response was produced for THIS request and
    // is not a recording of an earlier one.
    if (v.payload.str("client_nonce") != nonce_b64) {
        crypto::zeroize(const_cast<Bytes&>(eph_secret));
        return R::failure(Error::NonceMismatch, "server did not echo our nonce");
    }

    const std::int64_t server_time = v.payload.num("server_time");
    if (server_time > 0) {
        const std::int64_t delta = now_unix() - server_time;
        if (delta > kMaxClockSkewSec || delta < -kMaxClockSkewSec) {
            crypto::zeroize(const_cast<Bytes&>(eph_secret));
            return R::failure(Error::ClockSkew, "local clock differs from the server's");
        }
    }

    if (!v.payload.boolean_at("success")) {
        crypto::zeroize(const_cast<Bytes&>(eph_secret));
        return R::failure(map_wire_error(v.payload.str("error")), v.payload.str("error"));
    }

    Bytes server_eph;
    if (!crypto::base64_decode(v.payload.str("server_eph_pubkey"), server_eph)) {
        crypto::zeroize(const_cast<Bytes&>(eph_secret));
        return R::failure(Error::BadResponse, "server ephemeral key missing");
    }

    Bytes session_key;
    const bool derived = crypto::derive_session_key(
        eph_secret, server_eph, v.payload.str("session_id"), session_key);
    crypto::zeroize(const_cast<Bytes&>(eph_secret));
    if (!derived) {
        return R::failure(Error::BadResponse, "session key derivation failed");
    }

    LicenseInfo info;
    if (const auto* lic = v.payload.find("license");
        lic && lic->type == json::Value::Type::Object) {
        info.level        = int(lic->num("level"));
        info.expires_at   = lic->num("expires_at");
        info.devices_used = int(lic->num("devices_used"));
        info.max_devices  = int(lic->num("max_devices"));
    }

    auto impl = std::make_unique<SessionImpl>(
        impl_->app_id, impl_->public_key, impl_->base_url,
        v.payload.str("session_token"), std::move(session_key), info,
        v.payload.num("session_expires_at"), impl_->timeout_ms);

    return R::success(std::make_shared<Session>(std::move(impl)));
}

Result<bool> request_device_reset(const std::string& app_id,
                                  const std::string& public_key_b64,
                                  const std::string& base_url,
                                  const std::string& license_key) {
    Bytes public_key;
    if (!crypto::base64_decode(public_key_b64, public_key) ||
        public_key.size() != crypto::kEd25519Pub) {
        return Result<bool>::failure(Error::Internal, "public key is not 32 bytes");
    }

    std::string url = base_url;
    if (!url.empty() && url.back() == '/') url.pop_back();

    std::ostringstream body;
    body << R"({"app_id":")" << json::escape(app_id)
         << R"(","license_key":")" << json::escape(license_key) << R"("})";

    const auto v = call_endpoint(url, "/v1/device/reset", "device_reset",
                                 public_key, body.str(), kDefaultTimeoutMs);
    if (!v.ok) return Result<bool>::failure(v.error, v.message);

    if (!v.payload.boolean_at("success")) {
        return Result<bool>::failure(map_wire_error(v.payload.str("error")),
                                     v.payload.str("error"));
    }
    return Result<bool>::success(true);
}

} // namespace rudeauth
