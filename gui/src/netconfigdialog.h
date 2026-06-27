#pragma once

#include <QDialog>

class PontusClient;
class QTableWidget;

// Local network configuration (F-036): this machine's interfaces (IP, MAC,
// netmask) and the ports it is listening on. "Self" info — a live query of the
// host Pontus runs on, over pontus_local_config_json (no store needed).
class NetConfigDialog : public QDialog {
    Q_OBJECT
public:
    NetConfigDialog(PontusClient* client, QWidget* parent = nullptr);

private:
    void build();

    PontusClient* client_;
    QTableWidget* interfaces_ = nullptr;
    QTableWidget* listening_ = nullptr;
};
