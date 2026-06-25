#pragma once

#include <QDialog>

class PontusClient;
class QComboBox;
class TopologyView;

// Topology graph window (F-009): a scan selector over a force-directed
// TopologyView, rendering pontus_topology_json.
class TopologyDialog : public QDialog {
    Q_OBJECT
public:
    TopologyDialog(PontusClient* client, QWidget* parent = nullptr);

private slots:
    void onScanChanged();

private:
    PontusClient* client_;
    QComboBox* scan_ = nullptr;
    TopologyView* view_ = nullptr;
};
