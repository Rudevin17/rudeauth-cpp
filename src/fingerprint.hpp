// Hardware fingerprint collection.
//
// These values are client-supplied and therefore forgeable. Device binding
// deters casual licence sharing; it is not a control against a motivated
// attacker, and the SDK does not pretend otherwise.
//
// Several components are collected so the server's K-of-N matching can
// tolerate a replaced drive or a reinstall without costing the customer a
// device reset.
#pragma once

#include <string>
#include <vector>

namespace rudeauth::fingerprint {

// Minimum components the SDK will submit. Fewer than two is trivially forged
// and leaves no drift tolerance, so the SDK refuses rather than sending a weak
// identity the server would have to accept.
inline constexpr std::size_t kMinComponents = 2;

// collect gathers what this machine can report. Components that fail are
// skipped rather than substituted, because a placeholder shared across
// machines would make unrelated devices look identical.
std::vector<std::string> collect();

// label is a human-readable name shown in the vendor's device list.
std::string label();

} // namespace rudeauth::fingerprint
