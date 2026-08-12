// The RudeAuth integration, in full.
//
// Note what this example does NOT contain: any variable holding "is the user
// licensed". The program cannot run without the payload the server sends, so
// there is no branch for an attacker to invert.
#include <rudeauth/rudeauth.hpp>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <string>

namespace {

// ---------------------------------------------------------------------------
// Config file, FOR THIS EXAMPLE ONLY.
//
// Reading the app ID and public key from a file makes the example runnable
// without editing and rebuilding, which is what you want while evaluating.
//
// It is the wrong thing to do in a real client, and not for style reasons.
// The public key is what proves a response came from your server. Put it in a
// file and anyone can replace it with their own, point the base URL at a
// server they control, and your client will happily verify their forged
// replies. The whole signature check becomes theatre.
//
// In production: compile both values in. Neither is secret, and both must be
// beyond the reach of whoever is trying to bypass you.
// ---------------------------------------------------------------------------

std::map<std::string, std::string> load_config(const char* path) {
    std::map<std::string, std::string> cfg;
    std::ifstream in(path);
    if (!in) return cfg;

    std::string line;
    while (std::getline(in, line)) {
        // Strip a trailing CR so a file saved on Windows parses on both.
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;

        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        auto trim = [](std::string s) {
            const auto b = s.find_first_not_of(" \t");
            if (b == std::string::npos) return std::string{};
            const auto e = s.find_last_not_of(" \t");
            return s.substr(b, e - b + 1);
        };
        cfg[trim(line.substr(0, eq))] = trim(line.substr(eq + 1));
    }
    return cfg;
}

// Environment wins over the file, so a one-off run needs no edit at all.
std::string setting(const std::map<std::string, std::string>& cfg,
                    const char* key, const char* fallback) {
    if (const char* env = std::getenv(key); env && *env) return env;
    if (const auto it = cfg.find(key); it != cfg.end() && !it->second.empty()) return it->second;
    return fallback;
}

} // namespace

int main() {
    const auto cfg = load_config("rudeauth.ini");

    const std::string app_id     = setting(cfg, "RUDEAUTH_APP_ID", "");
    const std::string public_key = setting(cfg, "RUDEAUTH_PUBLIC_KEY", "");
    const std::string base_url   = setting(cfg, "RUDEAUTH_BASE_URL", "http://127.0.0.1:8099");

    if (app_id.empty() || public_key.empty()) {
        std::printf(
            "No application configured.\n\n"
            "  1. Copy rudeauth.example.ini to rudeauth.ini\n"
            "  2. Paste the Application ID and signing public key from the dashboard\n"
            "     (Applications -> Application credentials)\n\n"
            "Or set RUDEAUTH_APP_ID and RUDEAUTH_PUBLIC_KEY in the environment.\n");
        return 1;
    }

    std::printf("licence key: ");
    std::string key;
    if (!std::getline(std::cin, key)) return 1;

    // Trim the key before it is hashed.
    //
    // getline strips the newline but not a carriage return, so a key arriving
    // through a pipe keeps a trailing \r and hashes to something else
    // entirely. The server can only answer "licence invalid", which sends the
    // user hunting for a problem with their key rather than an invisible byte
    // after it. Pasted keys pick up spaces for the same reason.
    const auto first = key.find_first_not_of(" \t\r\n");
    const auto last  = key.find_last_not_of(" \t\r\n");
    key = (first == std::string::npos) ? std::string{} : key.substr(first, last - first + 1);
    if (key.empty()) {
        std::printf("no licence key given\n");
        return 1;
    }

    rudeauth::Client client(app_id, public_key, base_url);
    client.set_app_version("1.4.2");

    auto auth = client.authenticate(key);
    if (!auth.ok()) {
        // Show the user something they can act on. Expired and device-limit
        // are different problems with different remedies.
        std::printf("could not start: %s\n", rudeauth::to_string(auth.error()));
        return 1;
    }
    auto session = auth.value();

    std::printf("tier %d, %d/%d devices\n",
                session->info().level,
                session->info().devices_used,
                session->info().max_devices);

    // --- THIS is what makes patching pointless ----------------------------
    //
    // core.dll never shipped inside this binary. It arrives encrypted, opens
    // only with a session key derived from a handshake the server signed, and
    // the program has nothing to run without it. Removing the licence check
    // does not produce a working program — it produces a program with no
    // core.dll.
    auto payload = session->file("core.dll");
    if (!payload.ok()) {
        std::printf("could not load core module: %s\n", rudeauth::to_string(payload.error()));
        return 1;
    }
    std::printf("loaded core module: %zu bytes\n", payload.value().size());

    // Server-side configuration that changes between builds. A value that
    // never changes is convenience, not protection — rotate anything you rely
    // on for gating.
    if (auto offset = session->variable("offset"); offset.ok()) {
        std::printf("offset: %s\n", offset.value().c_str());
    }

    // ... run your program here, using payload.value() ...

    // The session heartbeats on its own thread until it goes out of scope,
    // then zeroizes its key.
    return 0;
}
