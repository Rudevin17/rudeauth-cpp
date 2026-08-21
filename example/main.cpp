// The RudeAuth integration, in full.
//
// Note what this example does NOT contain: any variable holding "is the user
// licensed". The program cannot run without the payload the server sends, so
// there is no branch for an attacker to invert.
#include <rudeauth/rudeauth.hpp>

#include <cstdio>
#include <iostream>
#include <string>

// The two values your application ships with. Replace these.
//
// Both are safe to embed: the public key verifies responses and cannot forge
// one, and the application ID identifies rather than authorises. Embedding is
// not a precaution about secrecy. It is what puts the trust anchor out of
// reach of whoever is trying to bypass you.
//
// Do not move these into a config file or an environment variable, however
// convenient that looks. The public key is what proves a response came from
// your server. Read it at runtime and anyone can swap it for their own, point
// the base URL at a server they run, and your client will happily verify their
// forged replies. The whole signature check becomes theatre.
constexpr const char* APP_ID     = "REPLACE_WITH_YOUR_APP_ID";
constexpr const char* PUBLIC_KEY = "REPLACE_WITH_YOUR_PUBLIC_KEY";
constexpr const char* BASE_URL   = "http://127.0.0.1:8099";

int main() {
    const std::string app_id     = APP_ID;
    const std::string public_key = PUBLIC_KEY;
    const std::string base_url   = BASE_URL;

    if (app_id == APP_ID || public_key == PUBLIC_KEY) {
        std::printf(
            "No application configured.\n\n"
            "  Edit APP_ID and PUBLIC_KEY at the top of main.cpp, then rebuild.\n"
            "  Both come from the dashboard: Applications -> Application credentials.\n\n"
            "  You are already compiling this, so there is nothing to save by\n"
            "  reading them from a file, and a public key read at runtime is one\n"
            "  an attacker can swap for their own.\n");
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
