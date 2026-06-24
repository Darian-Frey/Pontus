#pragma once

#include <QDialog>
#include <QProcess>

class QCheckBox;
class QLineEdit;
class QPlainTextEdit;
class QPushButton;

// "New scan" dialog (F-010, first cut). Collects targets/scope/ports, then runs a
// scan by shelling out to the privileged pontus-cli (D-008), streaming its output
// live. Scope is a mandatory field — the F-007 safety invariant made tangible.
class ScanDialog : public QDialog {
    Q_OBJECT
public:
    ScanDialog(QString cliPath, const QString& defaultDb, QWidget* parent = nullptr);

    // The store that was scanned into after a successful run (empty otherwise),
    // so the caller can reload it.
    QString scannedDatabase() const { return scannedDb_; }

private slots:
    void onRun();
    void onCopyTargetsToScope();
    void onBrowseDb();
    void onOutput();
    void onFinished(int exitCode, QProcess::ExitStatus status);

private:
    void setRunning(bool running);

    QString cliPath_;
    QString scannedDb_;
    QProcess* proc_ = nullptr;

    QLineEdit* targets_ = nullptr;
    QLineEdit* scope_ = nullptr;
    QLineEdit* tcpPorts_ = nullptr;
    QLineEdit* udpPorts_ = nullptr;
    QLineEdit* db_ = nullptr;
    QLineEdit* operator_ = nullptr;
    QCheckBox* noRdns_ = nullptr;
    QPlainTextEdit* output_ = nullptr;
    QPushButton* runBtn_ = nullptr;
    QPushButton* closeBtn_ = nullptr;
};
