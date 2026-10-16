#pragma once

#include <string>

namespace omarchy_kids::control {

// Shows a desktop notification through `notify-send`. The title and body are
// passed as separate arguments (no shell), and control characters are
// stripped first: the text can come from a child's free-text note. Needs no
// Qt and no event loop, so the headless `--poll` mode can use it. Failures
// (no notify-send, no session bus) are ignored — a missed notification must
// never break a poll.
void sendDesktopNotification(const std::string& title, const std::string& body);

// The plain-text form used for notification text: control characters removed
// and the length capped.
std::string sanitizeNotificationText(const std::string& text, size_t maxChars = 200);

} // namespace omarchy_kids::control
