#pragma once

#include <QDialog>

class PontusClient;
class QComboBox;
class QLabel;
class QTableWidget;

// Service/port heatmap (F-011): a host × open-service grid that makes shared
// exposure across the subnet pop at a glance. Columns are ordered most-shared
// first, so widely-open ports cluster on the left. Scoped to a single scan (a
// selector, defaulting to the latest) so every host is compared on the same port
// coverage — not each host's latest observation across scans, which mixes
// different port sets and up/down states.
class HeatmapDialog : public QDialog {
    Q_OBJECT
public:
    HeatmapDialog(PontusClient* client, QWidget* parent = nullptr);

private slots:
    void build();

private:
    void populateScans();

    PontusClient* client_;
    QComboBox* scan_ = nullptr;
    QTableWidget* table_ = nullptr;
    QLabel* summary_ = nullptr;
};
