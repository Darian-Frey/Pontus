#pragma once

#include <QDialog>

class PontusClient;
class QLabel;
class QTableWidget;

// Service/port heatmap (F-011): a host × open-service grid that makes shared
// exposure across the subnet pop at a glance. Columns are ordered most-shared
// first, so widely-open ports cluster on the left. Derived from each asset's
// latest observation — no new FFI surface.
class HeatmapDialog : public QDialog {
    Q_OBJECT
public:
    HeatmapDialog(PontusClient* client, QWidget* parent = nullptr);

private:
    void build();

    PontusClient* client_;
    QTableWidget* table_ = nullptr;
    QLabel* summary_ = nullptr;
};
