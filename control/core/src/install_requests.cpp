#include "omarchy-kids-control/install_requests.h"

#include <algorithm>
#include <cctype>

namespace omarchy_kids::control {

namespace {

bool isLowerAlnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
}

} // namespace

bool isValidPackageName(const std::string& name) {
    if (name.empty() || name.size() > 100) {
        return false;
    }
    if (name.front() == '-' || name.front() == '.') {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](char c) {
        return isLowerAlnum(c) || c == '@' || c == '.' || c == '_' || c == '+' || c == '-';
    });
}

bool isValidLoginName(const std::string& name) {
    if (name.empty() || name.size() > 32) {
        return false;
    }
    const char first = name.front();
    if (!((first >= 'a' && first <= 'z') || first == '_')) {
        return false;
    }
    return std::all_of(name.begin(), name.end(), [](char c) {
        return isLowerAlnum(c) || c == '_' || c == '-';
    });
}

bool isValidSshHost(const std::string& host) {
    if (host.empty() || host.size() > 255 || host.front() == '-') {
        return false;
    }
    return std::all_of(host.begin(), host.end(), [](char c) {
        return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '.' || c == '-' || c == ':';
    });
}

std::vector<std::string> adminInstallSshArgs(
    const HostEntry& host,
    const std::string& adminUser,
    const std::string& package,
    const std::string& knownHostsFile) {
    if (!isValidPackageName(package) || !isValidLoginName(adminUser) || !isValidSshHost(host.hostname)) {
        return {};
    }

    std::vector<std::string> argv = {"ssh", "-t", "-p", std::to_string(host.sshPort)};
    if (!knownHostsFile.empty()) {
        argv.insert(argv.end(), {
            "-o", "StrictHostKeyChecking=yes",
            "-o", "UserKnownHostsFile=" + knownHostsFile,
            "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", std::string("HostKeyAlias=") + kPinnedHostKeyAlias,
        });
    } else {
        argv.insert(argv.end(), {"-o", "StrictHostKeyChecking=accept-new"});
    }
    // The destination starts with the (validated) login name, so it can never
    // be read as an ssh option. The remaining arguments are the remote command;
    // ssh joins them into one string for the remote shell, which is safe here
    // only because the package name was validated above.
    argv.push_back(adminUser + "@" + host.hostname);
    argv.insert(argv.end(), {"sudo", "pacman", "-S", "--needed", "--", package});
    return argv;
}

std::string requestKey(const std::string& hostName, const InstallRequest& request) {
    return hostName + "|" + std::to_string(request.id) + "|" + request.requestedAt;
}

} // namespace omarchy_kids::control
