#include "scandialog.h"

#include <QCheckBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QVBoxLayout>

ScanDialog::ScanDialog(QString cliPath, const QString& defaultDb, QWidget* parent)
    : QDialog(parent), cliPath_(std::move(cliPath)) {
    setWindowTitle(QStringLiteral("New scan"));
    resize(720, 560);

    proc_ = new QProcess(this);
    proc_->setProcessChannelMode(QProcess::MergedChannels);
    connect(proc_, &QProcess::readyRead, this, &ScanDialog::onOutput);
    connect(proc_, &QProcess::finished, this, &ScanDialog::onFinished);

    targets_ = new QLineEdit;
    targets_->setPlaceholderText(QStringLiteral("e.g. 192.168.1.0/24 or a single host"));

    scope_ = new QLineEdit;
    scope_->setPlaceholderText(QStringLiteral("mandatory — nothing is scanned outside this"));
    auto* copyScope = new QPushButton(QStringLiteral("= targets"));
    copyScope->setToolTip(QStringLiteral("Copy the target range into scope"));
    connect(copyScope, &QPushButton::clicked, this, &ScanDialog::onCopyTargetsToScope);
    auto* scopeRow = new QWidget;
    auto* scopeLayout = new QHBoxLayout(scopeRow);
    scopeLayout->setContentsMargins(0, 0, 0, 0);
    scopeLayout->addWidget(scope_);
    scopeLayout->addWidget(copyScope);

    tcpPorts_ = new QLineEdit(QStringLiteral("22,80,443,445,3389,8080"));
    udpPorts_ = new QLineEdit;
    udpPorts_->setPlaceholderText(QStringLiteral("optional — e.g. 53,123,161,1900,5353"));

    db_ = new QLineEdit(defaultDb);
    auto* browse = new QPushButton(QStringLiteral("Browse…"));
    connect(browse, &QPushButton::clicked, this, &ScanDialog::onBrowseDb);
    auto* dbRow = new QWidget;
    auto* dbLayout = new QHBoxLayout(dbRow);
    dbLayout->setContentsMargins(0, 0, 0, 0);
    dbLayout->addWidget(db_);
    dbLayout->addWidget(browse);

    operator_ = new QLineEdit;
    operator_->setPlaceholderText(QStringLiteral("optional — recorded in the audit log"));
    noRdns_ = new QCheckBox(QStringLiteral("Skip reverse-DNS"));

    auto* form = new QFormLayout;
    form->addRow(QStringLiteral("Targets"), targets_);
    form->addRow(QStringLiteral("Scope *"), scopeRow);
    form->addRow(QStringLiteral("TCP ports"), tcpPorts_);
    form->addRow(QStringLiteral("UDP ports"), udpPorts_);
    form->addRow(QStringLiteral("Database"), dbRow);
    form->addRow(QStringLiteral("Operator"), operator_);
    form->addRow(QString(), noRdns_);

    auto* scopeNote = new QLabel(
        QStringLiteral("Scope is enforced before any packet is sent (F-007); it cannot be disabled."));
    scopeNote->setWordWrap(true);
    scopeNote->setStyleSheet(QStringLiteral("color: palette(mid);"));

    output_ = new QPlainTextEdit;
    output_->setReadOnly(true);
    output_->setFont(QFontDatabase::systemFont(QFontDatabase::FixedFont));
    output_->setPlaceholderText(QStringLiteral("Scan output appears here…"));

    runBtn_ = new QPushButton(QStringLiteral("Scan"));
    runBtn_->setDefault(true);
    connect(runBtn_, &QPushButton::clicked, this, &ScanDialog::onRun);
    closeBtn_ = new QPushButton(QStringLiteral("Close"));
    connect(closeBtn_, &QPushButton::clicked, this, &QDialog::accept);
    auto* buttons = new QDialogButtonBox;
    buttons->addButton(runBtn_, QDialogButtonBox::ActionRole);
    buttons->addButton(closeBtn_, QDialogButtonBox::RejectRole);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(form);
    layout->addWidget(scopeNote);
    layout->addWidget(output_, 1);
    layout->addWidget(buttons);

    if (cliPath_.isEmpty()) {
        output_->appendPlainText(
            QStringLiteral("pontus-cli not found. Put it on PATH, set PONTUS_CLI, or build the "
                           "workspace, then reopen this dialog."));
        runBtn_->setEnabled(false);
    }
}

void ScanDialog::onCopyTargetsToScope() {
    scope_->setText(targets_->text());
}

void ScanDialog::onBrowseDb() {
    const QString path = QFileDialog::getSaveFileName(
        this, QStringLiteral("Scan into database"), db_->text(),
        QStringLiteral("Pontus store (*.db);;All files (*)"), nullptr,
        QFileDialog::DontConfirmOverwrite);
    if (!path.isEmpty()) {
        db_->setText(path);
    }
}

void ScanDialog::onRun() {
    const QString targets = targets_->text().trimmed();
    const QString scope = scope_->text().trimmed();
    const QString db = db_->text().trimmed();
    if (targets.isEmpty() || scope.isEmpty() || db.isEmpty()) {
        output_->appendPlainText(QStringLiteral(
            "Targets, scope and database are all required. Scope is mandatory — "
            "nothing is scanned outside it."));
        return;
    }

    QStringList args;
    args << QStringLiteral("scan") << targets << QStringLiteral("--scope") << scope
         << QStringLiteral("--db") << db;
    const QString tcp = tcpPorts_->text().trimmed();
    if (!tcp.isEmpty()) {
        args << QStringLiteral("--ports") << tcp;
    }
    const QString udp = udpPorts_->text().trimmed();
    if (!udp.isEmpty()) {
        args << QStringLiteral("--udp-ports") << udp;
    }
    const QString op = operator_->text().trimmed();
    if (!op.isEmpty()) {
        args << QStringLiteral("--operator") << op;
    }
    if (noRdns_->isChecked()) {
        args << QStringLiteral("--no-rdns");
    }

    output_->clear();
    output_->appendPlainText(QStringLiteral("$ %1 %2\n").arg(cliPath_, args.join(QLatin1Char(' '))));
    // Hold the target db; confirmed as scannedDb_ only on a clean exit.
    scannedDb_.clear();
    db_->setProperty("pendingDb", db);

    setRunning(true);
    proc_->start(cliPath_, args);
}

void ScanDialog::onOutput() {
    output_->appendPlainText(QString::fromUtf8(proc_->readAll()).trimmed());
}

void ScanDialog::onFinished(int exitCode, QProcess::ExitStatus status) {
    setRunning(false);
    if (status == QProcess::CrashExit) {
        output_->appendPlainText(QStringLiteral("\n[scan process crashed]"));
        return;
    }
    if (exitCode == 0) {
        scannedDb_ = db_->property("pendingDb").toString();
        output_->appendPlainText(QStringLiteral("\n[scan complete — inventory will refresh on close]"));
    } else {
        output_->appendPlainText(QStringLiteral("\n[scan failed — exit code %1]").arg(exitCode));
    }
}

void ScanDialog::setRunning(bool running) {
    runBtn_->setEnabled(!running);
    targets_->setEnabled(!running);
    scope_->setEnabled(!running);
    tcpPorts_->setEnabled(!running);
    udpPorts_->setEnabled(!running);
    db_->setEnabled(!running);
    operator_->setEnabled(!running);
    noRdns_->setEnabled(!running);
    runBtn_->setText(running ? QStringLiteral("Scanning…") : QStringLiteral("Scan"));
}
