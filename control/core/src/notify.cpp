#include "omarchy-kids-control/notify.h"

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <vector>

extern char** environ;

namespace omarchy_kids::control {

std::string sanitizeNotificationText(const std::string& text, size_t maxChars) {
    std::string out;
    for (const char c : text) {
        if (out.size() >= maxChars) {
            break;
        }
        // Drop control characters (incl. ESC, newline, tab) and DEL; multi-byte
        // UTF-8 bytes (>= 0x80) pass through untouched.
        if (static_cast<unsigned char>(c) >= 0x20 && c != 0x7f) {
            out.push_back(c);
        }
    }
    return out;
}

void sendDesktopNotification(const std::string& title, const std::string& body) {
    const std::string safeTitle = sanitizeNotificationText(title, 100);
    const std::string safeBody = sanitizeNotificationText(body, 300);

    // `--` keeps a title that starts with `-` from being read as an option.
    std::vector<char*> argv = {
        const_cast<char*>("notify-send"),
        const_cast<char*>("--app-name=Omarchy Kids"),
        const_cast<char*>("--"),
        const_cast<char*>(safeTitle.c_str()),
        const_cast<char*>(safeBody.c_str()),
        nullptr,
    };

    pid_t pid = 0;
    if (posix_spawnp(&pid, "notify-send", nullptr, nullptr, argv.data(), environ) == 0) {
        int status = 0;
        waitpid(pid, &status, 0); // notify-send returns immediately
    }
}

} // namespace omarchy_kids::control
