#include "fingerprint.hpp"

#include <windows.h>

#include <cstdio>
#include <optional>

namespace rudeauth::fingerprint {
namespace {

std::optional<std::string> reg_string(HKEY root, const char* subkey, const char* value) {
    HKEY key{};
    if (RegOpenKeyExA(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY, &key) != ERROR_SUCCESS) {
        return std::nullopt;
    }
    char buf[512]{};
    DWORD size = sizeof(buf), type = 0;
    const auto rc = RegQueryValueExA(key, value, nullptr, &type,
                                     reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(key);

    if (rc != ERROR_SUCCESS || type != REG_SZ || size == 0) return std::nullopt;

    std::string s(buf, size - 1); // drop the trailing NUL
    while (!s.empty() && (s.back() == '\0' || s.back() == ' ')) s.pop_back();
    if (s.empty()) return std::nullopt;
    return s;
}

std::optional<std::string> volume_serial() {
    DWORD serial = 0;
    if (!GetVolumeInformationA("C:\\", nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
        return std::nullopt;
    }
    if (serial == 0) return std::nullopt;

    // snprintf rather than wsprintfA: the latter lives in user32.dll, which
    // would add a link dependency this library otherwise does not need. MinGW
    // resolved it silently; MSVC would fail to link unless the consumer added
    // user32 themselves.
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%08lX", static_cast<unsigned long>(serial));
    return std::string(buf);
}

} // namespace

std::vector<std::string> collect() {
    std::vector<std::string> out;

    auto push = [&out](const char* tag, std::optional<std::string> v) {
        // Each component is tagged so two different sources cannot collide on
        // an identical value.
        if (v && !v->empty()) out.push_back(std::string(tag) + ":" + *v);
    };

    push("machine-guid",
         reg_string(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid"));
    push("volume", volume_serial());
    push("cpu",
         reg_string(HKEY_LOCAL_MACHINE,
                    "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0", "ProcessorNameString"));
    push("bios",
         reg_string(HKEY_LOCAL_MACHINE,
                    "HARDWARE\\DESCRIPTION\\System\\BIOS", "SystemSerialNumber"));
    push("board",
         reg_string(HKEY_LOCAL_MACHINE,
                    "HARDWARE\\DESCRIPTION\\System\\BIOS", "BaseBoardProduct"));

    return out;
}

std::string label() {
    char name[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD size = ARRAYSIZE(name);
    if (GetComputerNameA(name, &size)) return std::string(name, size);
    return "unknown";
}

} // namespace rudeauth::fingerprint
