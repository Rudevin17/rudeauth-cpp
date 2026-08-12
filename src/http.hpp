// WinHTTP transport for the RudeAuth SDK.
//
// The protocol's security does not rest on TLS — every response is signed and
// verified against a pinned public key — so plain http is permitted for local
// development. TLS is still used whenever the URL says https.
#pragma once

#include <string>

namespace rudeauth::http {

struct Response {
    bool        transport_ok = false; // false means the server was unreachable
    int         status       = 0;
    std::string body;
    std::string error;
};

// post sends a JSON body and returns a size-capped response.
Response post(const std::string& url, const std::string& body,
              int timeout_ms, std::size_t max_response_bytes);

} // namespace rudeauth::http
