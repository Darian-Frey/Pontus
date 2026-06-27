#include "scandialog.h"

#include "uiutil.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFontDatabase>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QVBoxLayout>

ScanDialog::ScanDialog(QString cliPath, const QString& defaultDb, QWidget* parent)
    : QDialog(parent), cliPath_(std::move(cliPath)) {
    setWindowTitle(QStringLiteral("New scan"));
    resize(720, 560);

    proc_ = new QProcess(this);
    proc_->setProcessChannelMode(QProcess::MergedChannels);
    connect(proc_, &QProcess::readyRead, this, &ScanDialog::onOutput);
    connect(proc_, &QProcess::finished, this, &ScanDialog::onFinished);

    // Saveable scan profiles (F-010), persisted in QSettings (GUI-side config).
    profile_ = new QComboBox;
    auto* saveProfile = new QPushButton(QStringLiteral("Save…"));
    auto* deleteProfile = new QPushButton(QStringLiteral("Delete"));
    connect(profile_, &QComboBox::currentIndexChanged, this, &ScanDialog::onProfileSelected);
    connect(saveProfile, &QPushButton::clicked, this, &ScanDialog::onSaveProfile);
    connect(deleteProfile, &QPushButton::clicked, this, &ScanDialog::onDeleteProfile);
    auto* profileRow = new QHBoxLayout;
    profileRow->addWidget(new QLabel(QStringLiteral("Profile")));
    profileRow->addWidget(profile_, 1);
    profileRow->addWidget(saveProfile);
    profileRow->addWidget(deleteProfile);

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
    tcpPorts_->setPlaceholderText(QStringLiteral("ranges ok — 80,443,8000-8100 or 1-1024 or -"));
    topPorts_ = new QLineEdit;
    topPorts_->setPlaceholderText(QStringLiteral("optional — also the N most common TCP ports, e.g. 100"));
    udpPorts_ = new QLineEdit;
    udpPorts_->setPlaceholderText(QStringLiteral("optional — e.g. 53,123,161,1900,5353"));

    detector_ = new QComboBox;
    detector_->addItem(QStringLiteral("native (clean-room)"));
    detector_->addItem(QStringLiteral("nmap -sV (your install)"));
    assessVulns_ = new QCheckBox(QStringLiteral("Assess vulnerabilities (CVE/EPSS/KEV) — hits the network"));
    inspect_ = new QCheckBox(QStringLiteral("Deep-inspect TLS / HTTP on open ports"));

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
    form->addRow(QStringLiteral("Top ports"), topPorts_);
    form->addRow(QStringLiteral("UDP ports"), udpPorts_);
    form->addRow(QStringLiteral("Detector"), detector_);
    form->addRow(QStringLiteral("Database"), dbRow);
    form->addRow(QStringLiteral("Operator"), operator_);
    form->addRow(QString(), assessVulns_);
    form->addRow(QString(), inspect_);
    form->addRow(QString(), noRdns_);

    auto* scopeNote = new QLabel(
        QStringLiteral("Scope is enforced before any packet is sent (F-007); it cannot be disabled."));
    scopeNote->setWordWrap(true);
    applyMutedText(scopeNote);

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
    layout->addLayout(profileRow);
    layout->addLayout(form);
    layout->addWidget(scopeNote);
    layout->addWidget(output_, 1);
    layout->addWidget(buttons);

    loadProfileNames();

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
    const QString top = topPorts_->text().trimmed();
    if (!top.isEmpty()) {
        args << QStringLiteral("--top-ports") << top;
    }
    const QString udp = udpPorts_->text().trimmed();
    if (!udp.isEmpty()) {
        args << QStringLiteral("--udp-ports") << udp;
    }
    if (detector_->currentIndex() == 1) {
        args << QStringLiteral("--detector") << QStringLiteral("nmap");
    }
    if (assessVulns_->isChecked()) {
        args << QStringLiteral("--assess-vulns");
    }
    if (inspect_->isChecked()) {
        args << QStringLiteral("--inspect");
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
    topPorts_->setEnabled(!running);
    udpPorts_->setEnabled(!running);
    detector_->setEnabled(!running);
    assessVulns_->setEnabled(!running);
    inspect_->setEnabled(!running);
    db_->setEnabled(!running);
    operator_->setEnabled(!running);
    noRdns_->setEnabled(!running);
    runBtn_->setText(running ? QStringLiteral("Scanning…") : QStringLiteral("Scan"));
}

void ScanDialog::loadProfileNames() {
    QSettings settings;
    settings.beginGroup(QStringLiteral("profiles"));
    const QStringList names = settings.childGroups();
    settings.endGroup();

    profile_->blockSignals(true);
    profile_->clear();
    profile_->addItem(QStringLiteral("(no profile)"));
    profile_->addItems(names);
    profile_->blockSignals(false);
}

void ScanDialog::onProfileSelected(int index) {
    if (index <= 0) {
        return; // "(no profile)"
    }
    QSettings settings;
    settings.beginGroup(QStringLiteral("profiles/%1").arg(profile_->currentText()));
    targets_->setText(settings.value(QStringLiteral("targets")).toString());
    scope_->setText(settings.value(QStringLiteral("scope")).toString());
    tcpPorts_->setText(settings.value(QStringLiteral("tcp")).toString());
    topPorts_->setText(settings.value(QStringLiteral("top")).toString());
    udpPorts_->setText(settings.value(QStringLiteral("udp")).toString());
    detector_->setCurrentIndex(settings.value(QStringLiteral("detector")).toInt());
    assessVulns_->setChecked(settings.value(QStringLiteral("assess_vulns")).toBool());
    inspect_->setChecked(settings.value(QStringLiteral("inspect")).toBool());
    operator_->setText(settings.value(QStringLiteral("operator")).toString());
    noRdns_->setChecked(settings.value(QStringLiteral("no_rdns")).toBool());
    settings.endGroup();
}

void ScanDialog::onSaveProfile() {
    const QString suggested = profile_->currentIndex() > 0 ? profile_->currentText() : QString();
    bool ok = false;
    const QString name =
        QInputDialog::getText(this, QStringLiteral("Save scan profile"),
                              QStringLiteral("Profile name:"), QLineEdit::Normal, suggested, &ok)
            .trimmed();
    if (!ok || name.isEmpty()) {
        return;
    }
    QSettings settings;
    settings.beginGroup(QStringLiteral("profiles/%1").arg(name));
    settings.setValue(QStringLiteral("targets"), targets_->text());
    settings.setValue(QStringLiteral("scope"), scope_->text());
    settings.setValue(QStringLiteral("tcp"), tcpPorts_->text());
    settings.setValue(QStringLiteral("top"), topPorts_->text());
    settings.setValue(QStringLiteral("udp"), udpPorts_->text());
    settings.setValue(QStringLiteral("detector"), detector_->currentIndex());
    settings.setValue(QStringLiteral("assess_vulns"), assessVulns_->isChecked());
    settings.setValue(QStringLiteral("inspect"), inspect_->isChecked());
    settings.setValue(QStringLiteral("operator"), operator_->text());
    settings.setValue(QStringLiteral("no_rdns"), noRdns_->isChecked());
    settings.endGroup();

    loadProfileNames();
    profile_->setCurrentText(name);
}

void ScanDialog::onDeleteProfile() {
    if (profile_->currentIndex() <= 0) {
        return;
    }
    QSettings settings;
    settings.beginGroup(QStringLiteral("profiles"));
    settings.remove(profile_->currentText());
    settings.endGroup();
    loadProfileNames();
}
