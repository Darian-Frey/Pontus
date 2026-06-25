// Thin C++ wrapper over the pontus-ffi C ABI: owns the store handle and returns
// parsed JSON (Qt types), so the rest of the GUI never touches raw C strings.
#pragma once

#include <QJsonArray>
#include <QString>

#include "pontus.h"

class PontusClient {
public:
    PontusClient() = default;
    ~PontusClient();

    PontusClient(const PontusClient&) = delete;
    PontusClient& operator=(const PontusClient&) = delete;

    bool open(const QString& dbPath);
    void close();
    bool isOpen() const { return handle_ != nullptr; }
    QString dbPath() const { return dbPath_; }

    QString version();
    QJsonArray assets();
    QJsonArray scans(long long limit);
    QJsonArray assetHistory(long long assetId);
    QJsonArray diff(long long fromScan, long long toScan);
    QJsonArray topology(long long scanId);

    bool setBaseline(long long scanId);
    long long baseline(); // -1 if none set

private:
    PontusHandle* handle_ = nullptr;
    QString dbPath_;
};
