#pragma once

#include <string>
#include <vector>

#include "omarchy-kids-control/host_registry.h"

namespace omarchy_kids::control {

// One install request, as a child's agent reports it
// (`omarchy-kids-agent requests --json`, see agent/common/src/protocol.rs).
struct InstallRequest {
    long long id = 0;
    std::string package;
    std::string repo;
    std::string version;
    std::string description;
    std::string downloadSize;
    std::string note;        // free text typed by the child: show as plain text
    std::string status;      // pending | approved | denied | installed
    std::string requestedAt; // ISO 8601
};

// Everything below exists because the agent runs as the CHILD's own account:
// whatever it returns is untrusted input, and an approved request ends up as
// a command run as root on the child. So the parent's computer re-checks
// every value it uses to build that command, with the same strict rules the
// agent applies, before anything is executed.

// Arch package names: lowercase letters, digits and `@ . _ + -`, at most 100
// characters, not starting with `-` or `.`.
bool isValidPackageName(const std::string& name);

// A Linux login name for the admin account: lowercase letters, digits, `_`
// and `-`, starting with a letter or `_`, at most 32 characters.
bool isValidLoginName(const std::string& name);

// A host or IP for ssh: letters, digits, `.`, `-`, `:` (IPv6); not starting
// with `-` (ssh would read it as an option).
bool isValidSshHost(const std::string& host);

// The argv of the `ssh` command that installs `package` on the child as its
// admin account: `sudo pacman -S --needed -- <package>`, interactive (no
// --noconfirm) so the parent sees the dependencies and the password prompt.
// `knownHostsFile`, when non-empty, pins the child's SSH host key from
// pairing; otherwise the first connection is trusted on first use.
// Returns an EMPTY vector if the package, admin user or host fails
// validation — callers must treat that as "do not run anything".
std::vector<std::string> adminInstallSshArgs(
    const HostEntry& host,
    const std::string& adminUser,
    const std::string& package,
    const std::string& knownHostsFile);

// Identifies one request for the "already notified" bookkeeping. Includes the
// timestamp so that a child whose agent database was reset, and whose ids
// therefore start again from 1, still produces new notifications.
std::string requestKey(const std::string& hostName, const InstallRequest& request);

// The host-key alias the agent client and the admin install both use; must
// match `kHostKeyAlias` in agent_client.cpp.
inline constexpr const char* kPinnedHostKeyAlias = "omarchy-kids-child";

} // namespace omarchy_kids::control
