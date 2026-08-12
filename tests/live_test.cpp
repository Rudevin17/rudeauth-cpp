// Live integration test: the SDK against a real rudeauthd.
//
// Everything here exercises the actual protocol over HTTP. If these pass, a
// customer can integrate the SDK.
#include "rudeauth/rudeauth.hpp"

#include <cstdio>
#include <cstring>
#include <string>

namespace {

int g_failures = 0;
int g_checks   = 0;

void check(bool cond, const char* what) {
    ++g_checks;
    std::printf("  %s  %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) ++g_failures;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 6) {
        std::printf("usage: live_test <base_url> <app_id> <public_key_b64> <license_key> "
                    "<expected_variable_value> [file_name] [file_size]\n");
        return 2;
    }
    const std::string base_url   = argv[1];
    const std::string app_id     = argv[2];
    const std::string public_key = argv[3];
    const std::string license    = argv[4];
    const std::string want_var   = argv[5];
    const std::string file_name  = argc > 6 ? argv[6] : "";
    const std::size_t file_size  = argc > 7 ? std::size_t(std::atoll(argv[7])) : 0;

    std::printf("RudeAuth SDK live integration\n");

    // 1 — a valid licence authenticates -------------------------------------
    rudeauth::Client client(app_id, public_key, base_url);
    auto first = client.authenticate(license);
    check(first.ok(), "valid licence authenticates");
    if (!first.ok()) {
        std::printf("       error: %s (%s)\n",
                    rudeauth::to_string(first.error()), first.message().c_str());
        std::printf("%d checks, %d failures\n", g_checks, g_failures);
        return 1;
    }

    auto session = first.value();
    check(session->info().max_devices >= 1, "license info is populated");
    check(session->info().devices_used == 1, "exactly one device is bound");

    // 2 — a variable arrives, decrypted -------------------------------------
    {
        auto v = session->variable("offset");
        check(v.ok() && v.value() == want_var, "server-side variable decrypts correctly");
        if (v.ok() && v.value() != want_var) {
            std::printf("       got %s, want %s\n", v.value().c_str(), want_var.c_str());
        }
    }

    // 3 — a missing variable is an error, not an empty string ---------------
    {
        auto v = session->variable("no-such-variable");
        check(!v.ok(), "a missing variable reports an error rather than empty");
    }

    // 4 — an encrypted file arrives intact ----------------------------------
    if (!file_name.empty()) {
        auto f = session->file(file_name);
        check(f.ok(), "encrypted file downloads");
        if (f.ok()) {
            check(f.value().size() == file_size, "file is byte-exact in length");
        } else {
            std::printf("       error: %s (%s)\n",
                        rudeauth::to_string(f.error()), f.message().c_str());
        }
    }

    // 5 — relaunch on the same machine --------------------------------------
    //
    // The regression that would refuse every customer for a whole session TTL.
    {
        rudeauth::Client again(app_id, public_key, base_url);
        auto second = again.authenticate(license);
        check(second.ok(), "relaunching on the same machine authenticates again");
        if (!second.ok()) {
            std::printf("       error: %s (%s)\n",
                        rudeauth::to_string(second.error()), second.message().c_str());
        }
    }

    // 6 — an invalid licence yields NO session ------------------------------
    {
        rudeauth::Client c(app_id, public_key, base_url);
        auto bad = c.authenticate("RUDE-00000-00000-00000-00000");
        check(!bad.ok(), "an invalid licence yields no session");
        check(bad.error() == rudeauth::Error::LicenseInvalid,
              "an invalid licence reports LicenseInvalid");
    }

    // 7 — THE property the SDK exists for -----------------------------------
    //
    // A server that is not holding this application's private key cannot be
    // believed, no matter what it answers.
    {
        // A syntactically valid but different Ed25519 public key.
        const std::string other_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        rudeauth::Client c(app_id, other_key, base_url);
        auto forged = c.authenticate(license);
        check(!forged.ok(), "a response not signed by our key is refused");
        check(forged.error() == rudeauth::Error::SignatureInvalid,
              "the refusal is specifically SignatureInvalid");
    }

    // 8 — documented consequence of a single-session licence -----------------
    //
    // With max_concurrent_sessions = 1, the relaunch in check 5 took the only
    // slot, so the original session is correctly dead. This is not a bug: it
    // is what "one session" means, and the SDK reports it as SessionExpired
    // rather than pretending otherwise.
    {
        auto v = session->variable("offset");
        check(!v.ok() && v.error() == rudeauth::Error::SessionExpired,
              "on a one-session licence, a relaunch supersedes the older session");
    }

    std::printf("%d checks, %d failures\n", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
