#include "json.hpp"

#include <cstdlib>

namespace rudeauth::json {
namespace {

struct Parser {
    const std::string& s;
    std::size_t i = 0;

    explicit Parser(const std::string& text) : s(text) {}

    void skip_ws() {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) ++i;
    }

    bool literal(const char* lit) {
        const std::size_t n = std::char_traits<char>::length(lit);
        if (s.compare(i, n, lit) != 0) return false;
        i += n;
        return true;
    }

    bool parse_string(std::string& out) {
        if (i >= s.size() || s[i] != '"') return false;
        ++i;
        out.clear();

        while (i < s.size()) {
            const char c = s[i++];
            if (c == '"') return true;

            if (c != '\\') {
                out += c;
                continue;
            }
            if (i >= s.size()) return false;

            switch (const char esc = s[i++]) {
                case '"':  out += '"';  break;
                case '\\': out += '\\'; break;
                case '/':  out += '/';  break;
                case 'b':  out += '\b'; break;
                case 'f':  out += '\f'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                case 'u': {
                    if (i + 4 > s.size()) return false;
                    unsigned cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        const char h = s[i + k];
                        cp <<= 4;
                        if (h >= '0' && h <= '9')      cp |= unsigned(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= unsigned(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= unsigned(h - 'A' + 10);
                        else return false;
                    }
                    i += 4;
                    // UTF-8 encode. Surrogate pairs are not expected in our
                    // responses; a lone surrogate is passed through as-is
                    // rather than silently corrupting the byte stream.
                    if (cp < 0x80) {
                        out += char(cp);
                    } else if (cp < 0x800) {
                        out += char(0xC0 | (cp >> 6));
                        out += char(0x80 | (cp & 0x3F));
                    } else {
                        out += char(0xE0 | (cp >> 12));
                        out += char(0x80 | ((cp >> 6) & 0x3F));
                        out += char(0x80 | (cp & 0x3F));
                    }
                    break;
                }
                default:
                    (void)esc;
                    return false;
            }
        }
        return false; // unterminated
    }

    bool parse_number(double& out) {
        const std::size_t start = i;
        if (i < s.size() && (s[i] == '-' || s[i] == '+')) ++i;
        bool digits = false;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') { ++i; digits = true; }
        if (i < s.size() && s[i] == '.') {
            ++i;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') { ++i; digits = true; }
        }
        if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
            ++i;
            if (i < s.size() && (s[i] == '-' || s[i] == '+')) ++i;
            while (i < s.size() && s[i] >= '0' && s[i] <= '9') ++i;
        }
        if (!digits) return false;
        out = std::strtod(s.substr(start, i - start).c_str(), nullptr);
        return true;
    }

    bool parse_value(Value& v, int depth) {
        if (depth > 8) return false; // our shapes never nest this deep
        skip_ws();
        if (i >= s.size()) return false;

        switch (s[i]) {
            case '{': {
                ++i;
                v.type = Value::Type::Object;
                skip_ws();
                if (i < s.size() && s[i] == '}') { ++i; return true; }
                for (;;) {
                    skip_ws();
                    std::string key;
                    if (!parse_string(key)) return false;
                    skip_ws();
                    if (i >= s.size() || s[i] != ':') return false;
                    ++i;
                    Value child;
                    if (!parse_value(child, depth + 1)) return false;
                    v.object[key] = std::move(child);
                    skip_ws();
                    if (i < s.size() && s[i] == ',') { ++i; continue; }
                    if (i < s.size() && s[i] == '}') { ++i; return true; }
                    return false;
                }
            }
            case '[': {
                ++i;
                v.type = Value::Type::Array;
                skip_ws();
                if (i < s.size() && s[i] == ']') { ++i; return true; }
                for (;;) {
                    Value child;
                    if (!parse_value(child, depth + 1)) return false;
                    v.array.push_back(std::move(child));
                    skip_ws();
                    if (i < s.size() && s[i] == ',') { ++i; continue; }
                    if (i < s.size() && s[i] == ']') { ++i; return true; }
                    return false;
                }
            }
            case '"':
                v.type = Value::Type::String;
                return parse_string(v.string);
            case 't':
                if (!literal("true")) return false;
                v.type = Value::Type::Bool;
                v.boolean = true;
                return true;
            case 'f':
                if (!literal("false")) return false;
                v.type = Value::Type::Bool;
                v.boolean = false;
                return true;
            case 'n':
                if (!literal("null")) return false;
                v.type = Value::Type::Null;
                return true;
            default:
                v.type = Value::Type::Number;
                return parse_number(v.number);
        }
    }
};

} // namespace

bool parse(const std::string& text, Value& out) {
    Parser p(text);
    out = Value{};
    if (!p.parse_value(out, 0)) return false;
    p.skip_ws();
    // Trailing data means the input was not what it claimed to be.
    return p.i == text.size();
}

std::string escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (const unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    static const char* hex = "0123456789abcdef";
                    out += "\\u00";
                    out += hex[c >> 4];
                    out += hex[c & 15];
                } else {
                    out += char(c);
                }
        }
    }
    return out;
}

} // namespace rudeauth::json
