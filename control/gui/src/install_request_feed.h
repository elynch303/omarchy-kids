#pragma once

#include <QString>

#include <string>
#include <vector>

#include "omarchy-kids-control/install_requests.h"

// Parses what `omarchy-kids-agent requests --json` prints:
// {"ok": true, "data": {"requests": [...]}}. Returns false (and leaves `out`
// empty) if the reply is malformed or not ok.
//
// The agent runs as the child's account, so the reply is untrusted: entries
// whose package name fails isValidPackageName() are dropped, and text fields
// are only ever shown as plain text.
bool parseInstallRequests(const QString& agentJson, std::vector<omarchy_kids::control::InstallRequest>* out);

// Sends a desktop notification for each PENDING request that hasn't been
// notified about before, and remembers it (in
// ~/.local/share/omarchy-kids-control/notified-requests.json) so the window
// and the background timer never notify twice for the same request.
void notifyNewInstallRequests(
    const std::string& hostName,
    const std::vector<omarchy_kids::control::InstallRequest>& requests);

// The headless poll behind `omarchy-kids-control --poll`: asks every paired
// child for its pending requests and notifies about new ones. Needs no
// display or event loop.
void pollInstallRequestsHeadless();
