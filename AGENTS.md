# RudeAuth C++ SDK: rules for an AI agent

RudeAuth is a hosted software licensing service, not a user-identity or password
authentication provider. Your binary embeds an application id and an Ed25519
public key; every server response is signed and verified against that key before
any field is trusted.

## Rules

Follow these rules. They are not style preferences; breaking them removes the
protection the SDK exists to provide.

1. There is no "bool is_licensed()". Do not write one, and do not wrap the SDK in
   one. `authenticate()` returns a Session or an error; the gated calls exist only
   on a Session. Pass the Session to the code that needs it.
2. Embed the app id and the PUBLIC key in the binary. Both are safe to embed. Never
   read the public key from a config file an attacker could swap.
3. Verify before trust. The SDK verifies the signature over the raw response bytes
   before parsing. If you write your own client, never parse first and verify second.
4. No offline mode, no "last known good" cache. If the server is unreachable, calls
   fail. A cache is exactly what an attacker induces by blocking the network.
5. Gate real logic, not a splash screen. Move code or data the program genuinely
   needs into a server-delivered file/variable, so the program cannot function
   without a valid licence. A licence check the program runs fine without is deleted.
6. Rotate anything you rely on. A variable protects only while it changes faster than
   someone maintains a patch. Do not hardcode one "just for testing"; it ships.
7. Honest limits: device binding deters casual sharing; fingerprints are forgeable.
   Do not describe this as unbreakable.

Errors are specific (expired vs device-limit vs banned vs revoked). Handle them
distinctly; show the user the actionable ones.

## This SDK

Install: from source. Windows, C++17, static library, no package manager.

```
git clone https://github.com/Rudevin17/rudeauth-cpp.git
cd rudeauth-cpp
cmake -B build -S .
cmake --build build --config Release
```

```cpp
#include <rudeauth/rudeauth.hpp>

// Compiled in, not read from a file. A public key in a config file can be
// swapped for an attacker's, after which every signature check passes against
// a server they control.
constexpr auto APP_ID = "your-application-id";
constexpr auto PUBKEY = "your-public-key";

rudeauth::Client client(APP_ID, PUBKEY, "https://api.rudeauth.com");

auto auth = client.authenticate(user_entered_key);
if (!auth.ok()) {
    show(rudeauth::to_string(auth.error()));   // expired != device limit != banned
    return 1;
}
auto session = auth.value();                   // keep alive for the program's lifetime
```

`Result::ok()` reports whether the call succeeded; a rejected licence is `ok() ==
false` with a specific `Error` from `auth.error()` (`SignatureInvalid`,
`LicenseExpired`, `DeviceLimit`, `DeviceBlacklisted`, and so on). There is no
explicit close: `session` is an RAII object, so keep it alive for the program's
lifetime and it cleans up, including stopping the heartbeat, on destruction.

In CMake:

```cmake
add_subdirectory(rudeauth-cpp)
target_link_libraries(yourapp PRIVATE rudeauth)
```

## How to use this wrongly

Three real failure modes, in the order people hit them:

1. Fetching the payload and not using it. If your program runs fine without
   `core.dll`, an attacker deletes the call and ships. Gating only works when the
   program genuinely cannot function without what the server sends. Move real
   logic into the payload, not a splash screen.
2. Hardcoding a variable "just for testing". It ships. A variable is protection
   only while it changes faster than someone will maintain a patch; a constant
   delivered over the network is convenience. Rotate anything you rely on.
3. Wrapping the SDK in `bool is_licensed()`. This is the most common and the most
   damaging failure mode: it reintroduces exactly the patch target the API was
   shaped to remove. If you find yourself writing that helper, the design has
   been undone. Pass the `Session` to the code that needs it.
</content>
