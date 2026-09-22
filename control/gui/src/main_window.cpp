#include "main_window.h"
#include "install_request_feed.h"
#include "pairing_dialog.h"

#include "omarchy-kids-control/agent_client.h"

#include <algorithm>
#include <vector>

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMessageBox>
#include <QMetaObject>
#include <QProcess>
#include <QPushButton>
#include <QScopeGuard>
#include <QSpinBox>
#include <QString>
#include <QStringList>
#include <QThreadPool>
#include <QTimer>
#include <QToolButton>
#include <QVBoxLayout>

using omarchy_kids::control::AgentClient;
using omarchy_kids::control::HostEntry;
using omarchy_kids::control::InstallRequest;

namespace {
// While a host is selected in the dashboard, re-check it this often —
// there's no push channel from agentd, only pull (see AgentClient).
constexpr int kPollIntervalMs = 30000;

// Deletes a paired host's saved keypair (private key, .pub, .known_hosts) —
// but only files inside this app's own keys directory, so a hand-edited
// hosts.toml can't aim the removal at some other file on disk.
void deleteSavedKeyFiles(const HostEntry& host) {
    if (host.keyPath.empty()) {
        return;
    }
    const QString keysDir = QDir::cleanPath(QDir(PairingDialog::keysDirectory()).absolutePath()) + "/";
    const QString keyPath = QDir::cleanPath(QFileInfo(QString::fromStdString(host.keyPath)).absoluteFilePath());
    if (!keyPath.startsWith(keysDir)) {
        return;
    }
    for (const QString& suffix : {QString(), QStringLiteral(".pub"), QStringLiteral(".known_hosts"),
                                  QStringLiteral(".admin_known_hosts")}) {
        QFile::remove(keyPath + suffix);
    }
}

// Where the child's pinned SSH host key for the admin install is kept: next
// to the paired key, and always inside this app's own keys directory (only
// the file NAME is taken from hosts.toml).
QString adminKnownHostsPath(const HostEntry& host) {
    if (host.keyPath.empty()) {
        return {};
    }
    const QString name = QFileInfo(QString::fromStdString(host.keyPath)).fileName();
    if (name.isEmpty()) {
        return {};
    }
    return PairingDialog::keysDirectory() + "/" + name + ".admin_known_hosts";
}

// Opens a terminal that runs `sudo pacman -S --needed -- <package>` on the
// child as its admin account (the parent types that password there). The
// command comes from adminInstallSshArgs(), which refuses anything that
// fails validation; the terminal runs it with "$@", so nothing is re-parsed
// by a shell locally.
bool launchAdminInstall(const HostEntry& host, const std::string& package) {
    QString knownHosts;
    if (!host.sshHostPublicKey.empty()) {
        knownHosts = adminKnownHostsPath(host);
        if (!knownHosts.isEmpty()) {
            QDir().mkpath(QFileInfo(knownHosts).absolutePath());
            QFile file(knownHosts);
            if (file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
                file.write((std::string(omarchy_kids::control::kPinnedHostKeyAlias) + " " +
                            host.sshHostPublicKey + "\n").c_str());
            } else {
                knownHosts.clear(); // fall back to trust-on-first-use
            }
        }
    }

    const std::vector<std::string> argv = omarchy_kids::control::adminInstallSshArgs(
        host, host.adminUser, package, knownHosts.toStdString());
    if (argv.empty()) {
        return false;
    }

    const QString script = QStringLiteral(
        "\"$@\"; status=$?; echo; "
        "if [ \"$status\" -eq 0 ]; then echo 'Finished.'; "
        "else echo \"The install did not finish (exit code $status).\"; fi; "
        "read -rp 'Press Enter to close...' _");

    QStringList args = {QString::fromStdString("--title=Omarchy Kids: install " + package),
                        QStringLiteral("-e"), QStringLiteral("bash"), QStringLiteral("-c"), script,
                        QStringLiteral("_")};
    for (const std::string& a : argv) {
        args << QString::fromStdString(a);
    }
    return QProcess::startDetached(QStringLiteral("xdg-terminal-exec"), args);
}
} // namespace

MainWindow::MainWindow(QWidget* parent) : QWidget(parent) {
    setWindowTitle(tr("Omarchy Kids Control Center"));

    hostList_ = new QListWidget(this);
    connect(hostList_, &QListWidget::currentRowChanged, this, &MainWindow::pollSelectedHost);

    statusLabel_ = new QLabel(tr("Select a child to see their status."), this);
    statusLabel_->setWordWrap(true);

    eventsList_ = new QListWidget(this);

    refreshButton_ = new QPushButton(tr("Refresh"), this);
    connect(refreshButton_, &QPushButton::clicked, this, &MainWindow::pollSelectedHost);

    auto* pairButton = new QPushButton(tr("Pair a new child..."), this);
    connect(pairButton, &QPushButton::clicked, this, &MainWindow::openPairingDialog);

    unlockAppEdit_ = new QLineEdit(this);
    unlockAppEdit_->setPlaceholderText(tr("desktop id, e.g. org.kde.gcompris"));
    unlockMinutesSpin_ = new QSpinBox(this);
    unlockMinutesSpin_->setRange(1, 24 * 60);
    unlockMinutesSpin_->setValue(30);
    unlockMinutesSpin_->setSuffix(tr(" min"));
    unlockButton_ = new QPushButton(tr("Unlock"), this);
    connect(unlockButton_, &QPushButton::clicked, this, &MainWindow::unlockSelectedApp);

    auto* unlockLayout = new QHBoxLayout();
    unlockLayout->addWidget(new QLabel(tr("Unlock app:"), this));
    unlockLayout->addWidget(unlockAppEdit_, /*stretch=*/1);
    unlockLayout->addWidget(unlockMinutesSpin_);
    unlockLayout->addWidget(unlockButton_);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(hostList_);
    layout->addWidget(statusLabel_);
    layout->addLayout(unlockLayout);
    layout->addWidget(new QLabel(tr("Security events (this week):"), this));
    layout->addWidget(eventsList_);

    requestsList_ = new QListWidget(this);
    requestsList_->setMaximumHeight(160);
    requestsList_->setSelectionMode(QAbstractItemView::NoSelection);
    layout->addWidget(new QLabel(tr("Install requests:"), this));
    layout->addWidget(requestsList_);

    layout->addWidget(refreshButton_);
    layout->addWidget(pairButton);
    setLayout(layout);

    // Only the currently selected host is polled — there's no headless
    // polling mode yet (see root CLAUDE.md "Status"), so a severe event on
    // an unselected/unopened host won't notify until this host is selected
    // again. Tracked as a known limitation, not silently assumed away.
    pollTimer_ = new QTimer(this);
    connect(pollTimer_, &QTimer::timeout, this, &MainWindow::pollSelectedHost);
    pollTimer_->start(kPollIntervalMs);

    refreshHostList();
}

void MainWindow::refreshHostList() {
    hostList_->clear();
    for (const HostEntry& host : registry_.hosts()) {
        auto* item = new QListWidgetItem();
        item->setData(Qt::UserRole, QString::fromStdString(host.name));
        hostList_->addItem(item);

        // One row = the label plus a ✕ at the end to remove the pairing. The
        // label ignores the mouse so clicking the row text still selects it.
        auto* row = new QWidget(hostList_);
        auto* rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(6, 2, 2, 2);
        auto* label = new QLabel(
            QStringLiteral("%1 — %2:%3")
                .arg(QString::fromStdString(host.name), QString::fromStdString(host.hostname))
                .arg(host.sshPort),
            row);
        label->setAttribute(Qt::WA_TransparentForMouseEvents);
        auto* removeButton = new QToolButton(row);
        removeButton->setText(QStringLiteral("✕"));
        removeButton->setToolTip(tr("Remove this pairing"));
        removeButton->setAutoRaise(true);
        const std::string name = host.name;
        connect(removeButton, &QToolButton::clicked, this, [this, name]() { removeHost(name); });
        rowLayout->addWidget(label, /*stretch=*/1);
        rowLayout->addWidget(removeButton);

        item->setSizeHint(row->sizeHint());
        hostList_->setItemWidget(item, row);
    }
}

void MainWindow::removeHost(const std::string& name) {
    const auto& hosts = registry_.hosts();
    const auto it = std::find_if(hosts.begin(), hosts.end(), [&](const HostEntry& h) { return h.name == name; });
    if (it == hosts.end()) {
        return;
    }
    const HostEntry host = *it; // copy: removeHost() below invalidates `it`

    QMessageBox box(QMessageBox::Warning, tr("Remove pairing"),
                    tr("Remove %1 (%2:%3)?")
                        .arg(QString::fromStdString(host.name), QString::fromStdString(host.hostname))
                        .arg(host.sshPort),
                    QMessageBox::NoButton, this);
    box.setInformativeText(
        tr("This forgets the pairing on this computer and deletes its saved key. It does not change the "
           "child's computer: that still trusts the old key until you remove the matching line from "
           "%1's ~/.ssh/authorized_keys there, or pair again.")
            .arg(QString::fromStdString(host.username.empty() ? std::string("the child account") : host.username)));
    QPushButton* removeButton = box.addButton(tr("Remove"), QMessageBox::DestructiveRole);
    box.addButton(QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Cancel);
    box.exec();
    if (box.clickedButton() != removeButton) {
        return;
    }

    registry_.removeHost(name);
    deleteSavedKeyFiles(host);
    lastNotifiedAt_.erase(name);

    // Rebuild the list from the event loop, not from inside the ✕ button's
    // own clicked() handler: the rebuild deletes that very button.
    QTimer::singleShot(0, this, [this]() {
        refreshHostList();
        statusLabel_->setText(tr("Select a child to see their status."));
        eventsList_->clear();
        requestsList_->clear();
    });
}

void MainWindow::applyRequestsResult(const std::string& hostName, bool ok, const QString& requestsJson) {
    // Same guard as applyPollResult: a reply for a host removed in the
    // meantime has nothing left to update, and must not notify.
    const auto& knownHosts = registry_.hosts();
    if (std::none_of(knownHosts.begin(), knownHosts.end(),
                     [&](const HostEntry& h) { return h.name == hostName; })) {
        return;
    }

    std::vector<InstallRequest> requests;
    const bool parsed = ok && parseInstallRequests(requestsJson, &requests);
    if (parsed) {
        // Shared bookkeeping with the background timer, so a request that
        // already produced a notification there doesn't produce another here.
        notifyNewInstallRequests(hostName, requests);
    }

    const QListWidgetItem* current = hostList_->currentItem();
    const bool isCurrentSelection =
        current && current->data(Qt::UserRole).toString().toStdString() == hostName;
    if (!isCurrentSelection || requestDialogOpen_) {
        return; // never rebuild rows underneath an open dialog
    }

    requestsList_->clear();
    if (!parsed) {
        return;
    }
    for (const InstallRequest& r : requests) {
        const bool pending = r.status == "pending";
        if (!pending && r.status != "approved") {
            continue; // denied and installed ones are history, not something to act on
        }

        auto* item = new QListWidgetItem();
        requestsList_->addItem(item);

        auto* row = new QWidget(requestsList_);
        auto* rowLayout = new QHBoxLayout(row);
        rowLayout->setContentsMargins(6, 2, 2, 2);

        // Plain text on purpose: the note is whatever the child typed.
        QString text = QStringLiteral("%1 %2 (%3, %4)")
                           .arg(QString::fromStdString(r.package), QString::fromStdString(r.version),
                                QString::fromStdString(r.repo), QString::fromStdString(r.downloadSize));
        if (!r.note.empty()) {
            text += QStringLiteral(" — \"%1\"").arg(QString::fromStdString(r.note));
        }
        if (!pending) {
            text += tr(" — approved, not installed yet");
        }
        auto* label = new QLabel(text, row);
        label->setTextFormat(Qt::PlainText);
        label->setToolTip(QString::fromStdString(r.description));
        rowLayout->addWidget(label, /*stretch=*/1);

        auto* approveButton = new QPushButton(pending ? tr("Approve...") : tr("Install..."), row);
        connect(approveButton, &QPushButton::clicked, this,
                [this, hostName, r]() { approveRequest(hostName, r); });
        rowLayout->addWidget(approveButton);
        if (pending) {
            auto* denyButton = new QPushButton(tr("Deny"), row);
            connect(denyButton, &QPushButton::clicked, this, [this, hostName, r]() { denyRequest(hostName, r); });
            rowLayout->addWidget(denyButton);
        }

        item->setSizeHint(row->sizeHint());
        requestsList_->setItemWidget(item, row);
    }
}

void MainWindow::approveRequest(const std::string& hostName, const InstallRequest& request) {
    const auto& hosts = registry_.hosts();
    const auto it = std::find_if(hosts.begin(), hosts.end(), [&](const HostEntry& h) { return h.name == hostName; });
    if (it == hosts.end()) {
        return;
    }
    HostEntry host = *it; // copy: addHost() below can change the registry's storage

    // The agent runs as the child, so this name is untrusted; nothing below
    // may be built from it until it passes the same check the agent applies.
    if (!omarchy_kids::control::isValidPackageName(request.package)) {
        QMessageBox::warning(this, tr("Install request"),
                             tr("That request has a package name that isn't valid, so it was ignored."));
        return;
    }

    requestDialogOpen_ = true;
    const auto reopenPolling = qScopeGuard([this]() { requestDialogOpen_ = false; });

    const bool pending = request.status == "pending";
    QMessageBox box(QMessageBox::Question, tr("Install request"),
                    tr("%1 wants to install %2 %3")
                        .arg(QString::fromStdString(host.name), QString::fromStdString(request.package),
                             QString::fromStdString(request.version)),
                    QMessageBox::NoButton, this);
    box.setTextFormat(Qt::PlainText); // applies to the text below too: the note is the child's own words
    QString details = tr("%1\n\nFrom the %2 repository, download %3.")
                          .arg(QString::fromStdString(request.description), QString::fromStdString(request.repo),
                               QString::fromStdString(request.downloadSize));
    if (!request.note.empty()) {
        details += tr("\n\nTheir note: \"%1\"").arg(QString::fromStdString(request.note));
    }
    details += tr("\n\nThis opens a terminal that installs it on %1's computer as its admin account. "
                  "You type that account's password there; nothing is installed without it.")
                   .arg(QString::fromStdString(host.name));
    box.setInformativeText(details);
    QPushButton* go = box.addButton(pending ? tr("Approve and install...") : tr("Install..."),
                                    QMessageBox::AcceptRole);
    box.addButton(QMessageBox::Cancel);
    box.setDefaultButton(QMessageBox::Cancel);
    box.exec();
    if (box.clickedButton() != go) {
        return;
    }

    bool gotName = false;
    const QString adminName = QInputDialog::getText(
                                  this, tr("Admin account"),
                                  tr("Name of the admin account on %1's computer (the one that can use sudo):")
                                      .arg(QString::fromStdString(host.name)),
                                  QLineEdit::Normal, QString::fromStdString(host.adminUser), &gotName)
                                  .trimmed();
    if (!gotName) {
        return;
    }
    const std::string admin = adminName.toStdString();
    if (!omarchy_kids::control::isValidLoginName(admin)) {
        QMessageBox::warning(this, tr("Admin account"),
                             tr("That isn't a valid account name (lowercase letters, digits, _ and -)."));
        return;
    }
    if (admin != host.adminUser) {
        host.adminUser = admin; // remembered, so it's only asked once
        registry_.addHost(host);
    }

    if (pending) {
        const auto decided = AgentClient::run(host, {"decide-request", std::to_string(request.id), "approve"});
        if (!decided.ok) {
            QMessageBox::warning(this, tr("Install request"),
                                 tr("Could not record the approval on %1's computer, so nothing was started.")
                                     .arg(QString::fromStdString(host.name)));
            return;
        }
    }

    if (!launchAdminInstall(host, request.package)) {
        QMessageBox::warning(this, tr("Install request"),
                             tr("Could not open a terminal for the install (is xdg-terminal-exec available?)."));
        return;
    }
    // The agent notices the package once it's installed; check again soon so
    // the row moves on without waiting for the next 30-second poll.
    QTimer::singleShot(4000, this, &MainWindow::pollSelectedHost);
}

void MainWindow::denyRequest(const std::string& hostName, const InstallRequest& request) {
    const auto& hosts = registry_.hosts();
    const auto it = std::find_if(hosts.begin(), hosts.end(), [&](const HostEntry& h) { return h.name == hostName; });
    if (it == hosts.end()) {
        return;
    }
    const HostEntry host = *it;
    const auto result = AgentClient::run(host, {"decide-request", std::to_string(request.id), "deny"});
    if (!result.ok) {
        QMessageBox::warning(this, tr("Install request"),
                             tr("Could not record the answer on %1's computer.")
                                 .arg(QString::fromStdString(host.name)));
        return;
    }
    // Rebuild from the event loop: this runs inside the Deny button's own
    // clicked() handler, and the rebuild deletes that button.
    QTimer::singleShot(0, this, &MainWindow::pollSelectedHost);
}

void MainWindow::openPairingDialog() {
    PairingDialog dialog(registry_, this);
    if (dialog.exec() == QDialog::Accepted) {
        refreshHostList();
    }
}

void MainWindow::pollSelectedHost() {
    const int row = hostList_->currentRow();
    const auto& hosts = registry_.hosts();
    if (row < 0 || row >= static_cast<int>(hosts.size())) {
        return;
    }
    startPoll(hosts[static_cast<size_t>(row)]);
}

void MainWindow::startPoll(const HostEntry& host) {
    statusLabel_->setText(tr("Checking %1 ...").arg(QString::fromStdString(host.name)));

    // AgentClient::run blocks (it's a synchronous fork/exec + wait, see
    // control/core/src/agent_client.cpp) for up to its timeout — running it
    // on the GUI thread would freeze the window for that long on every poll.
    // QMetaObject::invokeMethod's context-object overload is used to hop
    // back safely: if `this` is destroyed before the worker finishes, the
    // queued call is simply dropped instead of touching a dangling pointer.
    HostEntry hostCopy = host;
    QThreadPool::globalInstance()->start([this, hostCopy]() {
        const auto statusResult = AgentClient::run(hostCopy, {"status", "--json"});
        const auto reportResult = AgentClient::run(hostCopy, {"report", "--week", "--json"});
        const auto requestsResult = AgentClient::run(hostCopy, {"requests", "--json"});

        const std::string hostName = hostCopy.name;
        const bool statusOk = statusResult.ok;
        const bool reportOk = reportResult.ok;
        const bool requestsOk = requestsResult.ok;
        const QString statusText = QString::fromStdString(statusResult.stdoutText);
        const QString reportText = QString::fromStdString(reportResult.stdoutText);
        const QString requestsText = QString::fromStdString(requestsResult.stdoutText);

        QMetaObject::invokeMethod(
            this,
            [this, hostName, statusOk, statusText, reportOk, reportText, requestsOk, requestsText]() {
                applyPollResult(hostName, statusOk, statusText, reportOk, reportText);
                applyRequestsResult(hostName, requestsOk, requestsText);
            },
            Qt::QueuedConnection);
    });
}

void MainWindow::applyPollResult(
    const std::string& hostName,
    bool statusOk, const QString& statusText,
    bool reportOk, const QString& reportJson) {
    // A poll that was still in flight when its host got removed (✕ button)
    // has nothing left to update, and must not raise notifications for a
    // pairing the parent just deleted.
    const auto& knownHosts = registry_.hosts();
    if (std::none_of(knownHosts.begin(), knownHosts.end(),
                     [&](const HostEntry& h) { return h.name == hostName; })) {
        return;
    }

    // A poll started for a host that's no longer selected (the parent
    // clicked a different child while it was in flight) shouldn't overwrite
    // what's on screen now — but it still gets to update notification
    // bookkeeping below, since a severe event doesn't stop mattering just
    // because the window moved on.
    const QListWidgetItem* current = hostList_->currentItem();
    const bool isCurrentSelection =
        current && current->data(Qt::UserRole).toString().toStdString() == hostName;

    if (isCurrentSelection) {
        if (!statusOk) {
            statusLabel_->setText(tr("%1: unreachable over SSH.").arg(QString::fromStdString(hostName)));
        } else {
            const QJsonDocument doc = QJsonDocument::fromJson(statusText.toUtf8());
            const QJsonObject envelope = doc.object();
            if (!doc.isObject() || !envelope.value("ok").toBool()) {
                statusLabel_->setText(tr("%1: agentd error: %2")
                                           .arg(QString::fromStdString(hostName), envelope.value("error").toString()));
            } else {
                const QJsonObject data = envelope.value("data").toObject();
                QStringList unlocked;
                for (const QJsonValue& v : data.value("unlocked_apps").toArray()) {
                    unlocked << v.toString();
                }
                statusLabel_->setText(
                    tr("Tier: %1 | Unlocked: %2 | Budget: %3/%4 min | Blocked window: %5 | Active: %6")
                        .arg(data.value("tier").toString(),
                             unlocked.isEmpty() ? tr("(none)") : unlocked.join(", "))
                        .arg(data.value("daily_used_minutes").toInt())
                        .arg(data.value("daily_budget_minutes").toInt())
                        .arg(data.value("in_blocked_window").toBool() ? tr("yes") : tr("no"),
                             data.value("active_app").toString(tr("(none)"))));
            }
        }

        eventsList_->clear();
        if (reportOk) {
            const QJsonDocument doc = QJsonDocument::fromJson(reportJson.toUtf8());
            const QJsonObject envelope = doc.object();
            if (doc.isObject() && envelope.value("ok").toBool()) {
                const QJsonArray eventsArray = envelope.value("data").toObject().value("security_events").toArray();
                // Copied out of QJsonArray first: its iterators dereference to
                // QJsonValueRef, which std::sort can't swap directly.
                std::vector<QJsonObject> events;
                events.reserve(static_cast<size_t>(eventsArray.size()));
                for (const QJsonValue& v : eventsArray) {
                    events.push_back(v.toObject());
                }
                // Newest first — ISO 8601 timestamps sort correctly as plain
                // strings, so this needs no date parsing.
                std::sort(events.begin(), events.end(), [](const QJsonObject& a, const QJsonObject& b) {
                    return a.value("occurred_at").toString() > b.value("occurred_at").toString();
                });
                for (const QJsonObject& ev : events) {
                    const QString severity = ev.value("severity").toString();
                    auto* item = new QListWidgetItem(
                        tr("[%1] %2 (%3)%4")
                            .arg(ev.value("occurred_at").toString(), ev.value("event_type").toString(), severity,
                                 ev.value("detail").isNull() ? QString()
                                                              : QStringLiteral(" — ") + ev.value("detail").toString()));
                    if (severity == QStringLiteral("severe")) {
                        item->setForeground(Qt::red);
                    }
                    eventsList_->addItem(item);
                }
            }
        }
    }

    if (reportOk) {
        notifySevereEvents(hostName, reportJson);
    }
}

void MainWindow::unlockSelectedApp() {
    const int row = hostList_->currentRow();
    const auto& hosts = registry_.hosts();
    if (row < 0 || row >= static_cast<int>(hosts.size())) {
        return;
    }
    const QString app = unlockAppEdit_->text().trimmed();
    if (app.isEmpty()) {
        statusLabel_->setText(tr("Enter a desktop id to unlock (e.g. org.kde.gcompris)."));
        return;
    }

    HostEntry hostCopy = hosts[static_cast<size_t>(row)];
    const int minutes = unlockMinutesSpin_->value();
    unlockButton_->setEnabled(false);
    statusLabel_->setText(tr("Unlocking %1 on %2 ...").arg(app, QString::fromStdString(hostCopy.name)));

    QThreadPool::globalInstance()->start([this, hostCopy, app, minutes]() {
        const auto result = AgentClient::run(
            hostCopy,
            {"unlock", app.toStdString(), "--minutes", std::to_string(minutes), "--json"});

        const std::string hostName = hostCopy.name;
        const bool ok = result.ok;
        const QString resultJson = QString::fromStdString(result.stdoutText);

        QMetaObject::invokeMethod(
            this,
            [this, hostName, ok, resultJson]() { applyUnlockResult(hostName, ok, resultJson); },
            Qt::QueuedConnection);
    });
}

void MainWindow::applyUnlockResult(const std::string& hostName, bool ok, const QString& resultJson) {
    unlockButton_->setEnabled(true);

    const QListWidgetItem* current = hostList_->currentItem();
    const bool isCurrentSelection =
        current && current->data(Qt::UserRole).toString().toStdString() == hostName;
    if (!isCurrentSelection) {
        return;
    }

    if (!ok) {
        statusLabel_->setText(tr("%1: unlock failed — unreachable over SSH.").arg(QString::fromStdString(hostName)));
        return;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(resultJson.toUtf8());
    const QJsonObject envelope = doc.object();
    if (!doc.isObject() || !envelope.value("ok").toBool()) {
        statusLabel_->setText(tr("%1: unlock rejected by agentd: %2")
                                   .arg(QString::fromStdString(hostName), envelope.value("error").toString()));
        return;
    }
    unlockAppEdit_->clear();
    // Re-poll immediately so the status line/unlocked-apps list reflects the
    // new unlock right away instead of waiting for the next timer tick.
    pollSelectedHost();
}

void MainWindow::notifySevereEvents(const std::string& hostName, const QString& reportJson) {
    const QJsonDocument doc = QJsonDocument::fromJson(reportJson.toUtf8());
    if (!doc.isObject()) {
        return;
    }
    const QJsonObject envelope = doc.object();
    if (!envelope.value("ok").toBool()) {
        return;
    }
    const QJsonArray events = envelope.value("data").toObject().value("security_events").toArray();

    // First poll of a host this session: just learn where "already seen"
    // starts, without notifying — otherwise every pre-existing severe event
    // in that child's history would fire a notification the moment Control
    // Center opens, which is noise, not a real-time alert.
    const auto it = lastNotifiedAt_.find(hostName);
    const bool firstPollThisSession = (it == lastNotifiedAt_.end());
    const std::string newestSeen = firstPollThisSession ? std::string() : it->second;
    std::string newestThisPoll = newestSeen;

    for (const QJsonValue& v : events) {
        const QJsonObject ev = v.toObject();
        if (ev.value("severity").toString() != QStringLiteral("severe")) {
            continue;
        }
        const std::string occurredAt = ev.value("occurred_at").toString().toStdString();
        if (occurredAt > newestThisPoll) {
            newestThisPoll = occurredAt;
        }
        if (firstPollThisSession || occurredAt <= newestSeen) {
            continue;
        }
        QProcess::startDetached(
            "notify-send",
            {tr("Omarchy Kids: %1").arg(QString::fromStdString(hostName)),
             tr("%1%2")
                 .arg(ev.value("event_type").toString(),
                      ev.value("detail").isNull() ? QString() : QStringLiteral(" — ") + ev.value("detail").toString())});
    }
    lastNotifiedAt_[hostName] = newestThisPoll;
}
