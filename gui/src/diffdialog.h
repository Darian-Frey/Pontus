#pragma once

#include <QDialog>

class PontusClient;
class QCheckBox;
class QComboBox;
class QLabel;
class QTableWidget;

// Drift view (F-014): compare two scans and show new/vanished hosts, opened/closed
// ports and address moves, colour-coded. Reads pontus_diff_json through the shim —
// the time-travel insight made explicit, and the headline differentiator vs Zenmap.
class DiffDialog : public QDialog {
    Q_OBJECT
public:
    DiffDialog(PontusClient* client, QWidget* parent = nullptr);

private slots:
    void recompute();

private:
    void populateScans();

    PontusClient* client_;
    QComboBox* from_ = nullptr;
    QComboBox* to_ = nullptr;
    QCheckBox* showUnchanged_ = nullptr;
    QTableWidget* table_ = nullptr;
    QLabel* summary_ = nullptr;
};
