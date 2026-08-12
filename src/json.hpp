// A minimal JSON reader for RudeAuth's own response shapes.
//
// This is deliberately small rather than a general-purpose library. It only
// ever runs on bytes that have already passed Ed25519 verification, so it is
// not a security boundary — which is exactly why a ~200 line reader a customer
// can audit beats a large dependency here.
//
// It supports objects, arrays of strings, strings, numbers, booleans and null,
// with one level of nesting. It rejects trailing data and unterminated strings
// rather than guessing.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace rudeauth::json {

struct Value {
    enum class Type { Null, Bool, Number, String, Object, Array } type = Type::Null;

    bool                          boolean = false;
    double                        number  = 0;
    std::string                   string;
    std::map<std::string, Value>  object;
    std::vector<Value>            array;

    bool has(const std::string& key) const { return object.find(key) != object.end(); }

    const Value* find(const std::string& key) const {
        const auto it = object.find(key);
        return it == object.end() ? nullptr : &it->second;
    }

    std::string str(const std::string& key, const std::string& fallback = {}) const {
        const auto* v = find(key);
        return (v && v->type == Type::String) ? v->string : fallback;
    }

    std::int64_t num(const std::string& key, std::int64_t fallback = 0) const {
        const auto* v = find(key);
        return (v && v->type == Type::Number) ? static_cast<std::int64_t>(v->number) : fallback;
    }

    bool boolean_at(const std::string& key, bool fallback = false) const {
        const auto* v = find(key);
        return (v && v->type == Type::Bool) ? v->boolean : fallback;
    }
};

// parse returns false on any malformed input. It never partially succeeds.
bool parse(const std::string& text, Value& out);

// escape renders a string as a JSON string body, without surrounding quotes.
std::string escape(const std::string& s);

} // namespace rudeauth::json
