#include "pontusclient.h"

#include <QJsonDocument>

namespace {
// Parse a JSON string returned by the shim into a QJsonArray, then free it per the
// ownership contract (Rust allocated it; we must call pontus_string_free).
QJsonArray parseAndFree(char* json) {
    if (!json) {
        return {};
    }
    const QJsonDocument doc = QJsonDocument::fromJson(QByteArray(json));
    pontus_string_free(json);
    return doc.array();
}
} // namespace

PontusClient::~PontusClient() {
    close();
}

bool PontusClient::open(const QString& dbPath) {
    close();
    const QByteArray utf8 = dbPath.toUtf8();
    handle_ = pontus_open(utf8.constData());
    if (handle_) {
        dbPath_ = dbPath;
    }
    return handle_ != nullptr;
}

void PontusClient::close() {
    if (handle_) {
        pontus_close(handle_);
        handle_ = nullptr;
    }
    dbPath_.clear();
}

QString PontusClient::version() {
    char* v = pontus_version();
    const QString s = v ? QString::fromUtf8(v) : QString();
    if (v) {
        pontus_string_free(v);
    }
    return s;
}

QJsonArray PontusClient::assets() {
    return handle_ ? parseAndFree(pontus_assets_json(handle_)) : QJsonArray{};
}

QJsonArray PontusClient::scans(long long limit) {
    return handle_ ? parseAndFree(pontus_scans_json(handle_, limit)) : QJsonArray{};
}

QJsonArray PontusClient::assetHistory(long long assetId) {
    return handle_ ? parseAndFree(pontus_asset_history_json(handle_, assetId)) : QJsonArray{};
}

QJsonArray PontusClient::diff(long long fromScan, long long toScan) {
    return handle_ ? parseAndFree(pontus_diff_json(handle_, fromScan, toScan)) : QJsonArray{};
}

QJsonArray PontusClient::topology(long long scanId) {
    return handle_ ? parseAndFree(pontus_topology_json(handle_, scanId)) : QJsonArray{};
}

QJsonArray PontusClient::risk(long long scanId) {
    return handle_ ? parseAndFree(pontus_risk_json(handle_, scanId)) : QJsonArray{};
}

QJsonArray PontusClient::observations(long long scanId) {
    return handle_ ? parseAndFree(pontus_observations_json(handle_, scanId)) : QJsonArray{};
}

QJsonArray PontusClient::findings(long long scanId) {
    return handle_ ? parseAndFree(pontus_findings_json(handle_, scanId)) : QJsonArray{};
}

QJsonObject PontusClient::localConfig() {
    char* json = pontus_local_config_json(); // no handle — it queries this machine
    if (!json) {
        return {};
    }
    const QJsonObject obj = QJsonDocument::fromJson(QByteArray(json)).object();
    pontus_string_free(json);
    return obj;
}

bool PontusClient::setBaseline(long long scanId) {
    return handle_ ? pontus_set_baseline(handle_, scanId) : false;
}

long long PontusClient::baseline() {
    return handle_ ? pontus_baseline(handle_) : -1;
}
