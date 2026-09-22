#include "install_request_feed.h"

#include "omarchy-kids-control/agent_client.h"
#include "omarchy-kids-control/host_registry.h"
#include "omarchy-kids-control/notify.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSaveFile>
#include <QStringList>

#include <set>

using omarchy_kids::control::AgentClient;
using omarchy_kids::control::HostEntry;
using omarchy_kids::control::HostRegistry;
using omarchy_kids::control::InstallRequest;

namespace {

// Keeps the file small: only the most recent keys matter, because requests
// older than that are long since decided.
constexpr int kMaxRememberedKeys = 500;

QString notifiedFilePath() {
    return QDir::homePath() + "/.local/share/omarchy-kids-control/notified-requests.json";
}

std::set<std::string> loadNotifiedKeys() {
    std::set<std::string> keys;
    QFile file(notifiedFilePath());
    if (!file.open(QIODevice::ReadOnly)) {
        return keys;
    }
    const QJsonDocument doc = QJsonDocument::fromJson(file.readAll());
    for (const QJsonValue& v : doc.array()) {
        keys.insert(v.toString().toStdString());
    }
    return keys;
}

void saveNotifiedKeys(const std::set<std::string>& keys) {
    QJsonArray array;
    int skip = static_cast<int>(keys.size()) - kMaxRememberedKeys;
    for (const std::string& key : keys) {
        if (skip-- > 0) {
            continue;
        }
        array.append(QString::fromStdString(key));
    }
    QDir().mkpath(QFileInfo(notifiedFilePath()).absolutePath());
    QSaveFile out(notifiedFilePath()); // atomic: never leaves a half-written file
    if (out.open(QIODevice::WriteOnly)) {
        out.write(QJsonDocument(array).toJson(QJsonDocument::Compact));
        out.commit();
    }
}

} // namespace

bool parseInstallRequests(const QString& agentJson, std::vector<InstallRequest>* out) {
    out->clear();
    const QJsonDocument doc = QJsonDocument::fromJson(agentJson.toUtf8());
    if (!doc.isObject()) {
        return false;
    }
    const QJsonObject envelope = doc.object();
    if (!envelope.value("ok").toBool()) {
        return false;
    }
    const QJsonArray array = envelope.value("data").toObject().value("requests").toArray();
    for (const QJsonValue& v : array) {
        const QJsonObject o = v.toObject();
        InstallRequest r;
        r.id = static_cast<long long>(o.value("id").toDouble());
        r.package = o.value("package").toString().toStdString();
        r.repo = o.value("repo").toString().toStdString();
        r.version = o.value("version").toString().toStdString();
        r.description = o.value("description").toString().toStdString();
        r.downloadSize = o.value("download_size").toString().toStdString();
        r.note = o.value("note").toString().toStdString();
        r.status = o.value("status").toString().toStdString();
        r.requestedAt = o.value("requested_at").toString().toStdString();
        if (r.id <= 0 || !omarchy_kids::control::isValidPackageName(r.package)) {
            continue; // untrusted input: never keep an entry we couldn't safely act on
        }
        out->push_back(std::move(r));
    }
    return true;
}

void notifyNewInstallRequests(const std::string& hostName, const std::vector<InstallRequest>& requests) {
    std::set<std::string> notified = loadNotifiedKeys();
    bool changed = false;

    for (const InstallRequest& r : requests) {
        if (r.status != "pending") {
            continue;
        }
        const std::string key = omarchy_kids::control::requestKey(hostName, r);
        if (notified.count(key) != 0) {
            continue;
        }

        std::string body = r.description;
        if (!r.downloadSize.empty()) {
            body += " (" + r.downloadSize + ")";
        }
        if (!r.note.empty()) {
            body += " — \"" + r.note + "\"";
        }
        body += ". Open the Control Center to approve or deny.";
        omarchy_kids::control::sendDesktopNotification(hostName + " wants to install " + r.package, body);

        notified.insert(key);
        changed = true;
    }

    if (changed) {
        saveNotifiedKeys(notified);
    }
}

void pollInstallRequestsHeadless() {
    HostRegistry registry;
    for (const HostEntry& host : registry.hosts()) {
        const auto result = AgentClient::run(host, {"requests", "--json", "--status", "pending"});
        if (!result.ok) {
            continue;
        }
        std::vector<InstallRequest> pending;
        if (parseInstallRequests(QString::fromStdString(result.stdoutText), &pending)) {
            notifyNewInstallRequests(host.name, pending);
        }
    }
}
