#pragma once

#include <QDialog>

class PontusClient;
class QComboBox;
class QLabel;
class QTableWidget;

// Plugin findings view (F-020): the results plugins produced during a scan
// (`scan --plugins` / the New-scan dialog's plugins directory), one row per
// finding, severity-coloured and sortable. Reads pontus_findings_json through the
// shim. Scoped to a single scan via a selector (newest first).
class FindingsDialog : public QDialog {
    Q_OBJECT
public:
    FindingsDialog(PontusClient* client, QWidget* parent = nullptr);

private slots:
    void recompute();

private:
    void populateScans();

    PontusClient* client_ = nullptr;
    QComboBox* scan_ = nullptr;
    QTableWidget* table_ = nullptr;
    QLabel* summary_ = nullptr;
};
