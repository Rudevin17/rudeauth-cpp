#include "http.hpp"

#include <windows.h>
#include <winhttp.h>

#include <string>
#include <vector>

namespace rudeauth::http {
namespace {

std::wstring widen(const std::string& s) {
    if (s.empty()) return {};
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), nullptr, 0);
    std::wstring out(std::size_t(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), int(s.size()), out.data(), n);
    return out;
}

struct Handle {
    HINTERNET h = nullptr;
    explicit Handle(HINTERNET handle) : h(handle) {}
    ~Handle() { if (h) WinHttpCloseHandle(h); }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
    explicit operator bool() const { return h != nullptr; }
};

Response fail(const char* what) {
    Response r;
    r.transport_ok = false;
    r.error = what;
    return r;
}

} // namespace

Response post(const std::string& url, const std::string& body,
              int timeout_ms, std::size_t max_response_bytes) {
    const std::wstring wurl = widen(url);

    URL_COMPONENTS parts{};
    parts.dwStructSize = sizeof(parts);
    wchar_t host[256]{}, path[2048]{};
    parts.lpszHostName = host;      parts.dwHostNameLength = ARRAYSIZE(host);
    parts.lpszUrlPath  = path;      parts.dwUrlPathLength  = ARRAYSIZE(path);

    if (!WinHttpCrackUrl(wurl.c_str(), DWORD(wurl.size()), 0, &parts)) {
        return fail("malformed url");
    }

    Handle session(WinHttpOpen(L"RudeAuth-SDK/1",
                               WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session) return fail("WinHttpOpen failed");

    WinHttpSetTimeouts(session.h, timeout_ms, timeout_ms, timeout_ms, timeout_ms);

    Handle connect(WinHttpConnect(session.h, host, parts.nPort, 0));
    if (!connect) return fail("WinHttpConnect failed");

    const bool secure = parts.nScheme == INTERNET_SCHEME_HTTPS;
    Handle request(WinHttpOpenRequest(connect.h, L"POST", path, nullptr,
                                      WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES,
                                      secure ? WINHTTP_FLAG_SECURE : 0));
    if (!request) return fail("WinHttpOpenRequest failed");

    static const wchar_t* kHeaders = L"Content-Type: application/json\r\n";

    if (!WinHttpSendRequest(request.h, kHeaders, DWORD(-1),
                            const_cast<char*>(body.data()), DWORD(body.size()),
                            DWORD(body.size()), 0)) {
        return fail("WinHttpSendRequest failed");
    }
    if (!WinHttpReceiveResponse(request.h, nullptr)) {
        return fail("WinHttpReceiveResponse failed");
    }

    Response out;
    out.transport_ok = true;

    DWORD status = 0, status_size = sizeof(status);
    if (WinHttpQueryHeaders(request.h,
                            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &status, &status_size,
                            WINHTTP_NO_HEADER_INDEX)) {
        out.status = int(status);
    }

    std::vector<char> chunk(8192);
    for (;;) {
        DWORD available = 0;
        if (!WinHttpQueryDataAvailable(request.h, &available)) break;
        if (available == 0) break;

        while (available > 0) {
            const DWORD want = available < chunk.size() ? available : DWORD(chunk.size());
            DWORD read = 0;
            if (!WinHttpReadData(request.h, chunk.data(), want, &read) || read == 0) {
                available = 0;
                break;
            }
            // Cap the body: a hostile or broken server must not be able to
            // exhaust the client's memory.
            if (out.body.size() + read > max_response_bytes) {
                out.body.append(chunk.data(), max_response_bytes - out.body.size());
                return out;
            }
            out.body.append(chunk.data(), read);
            available -= read;
        }
    }
    return out;
}

} // namespace rudeauth::http
