#pragma once

#include <QDialog>
#include <QJsonArray>

class PontusClient;
class QComboBox;
class QLabel;
class QTableWidget;

// Vulnerability triage queue (F-015, C-002): hosts ranked by exploitation-weighted
// risk — KEV first, then EPSS, then CVSS — with a per-host CVE breakdown. Reads
// pontus_risk_json through the shim. This is the "fix-this-first" view the roadmap
// calls the single feature that most elevates the tool over a severity-sorted list.
class RiskDialog : public QDialog {
    Q_OBJECT
public:
    RiskDialog(PontusClient* client, QWidget* parent = nullptr);

private slots:
    void recompute();
    void onHostSelected();

private:
    void populateScans();

    PontusClient* client_;
    QComboBox* scan_ = nullptr;
    QTableWidget* hosts_ = nullptr;
    QTableWidget* vulns_ = nullptr;
    QLabel* summary_ = nullptr;
    QJsonArray ranked_; // ranked hosts for the selected scan
};
