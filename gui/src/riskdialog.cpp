#include "riskdialog.h"

#include "pontusclient.h"
#include "uiutil.h"

#include <QComboBox>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QFont>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QSplitter>
#include <QTableWidget>
#include <QUrl>
#include <QVBoxLayout>

namespace {
// Colour for a risk band; muted (invalid) for the low/informational tail so the
// table reads as a heatmap of what actually needs attention. KEV always lands in
// the Critical band (see the core risk model), so it inherits the deepest red.
QColor bandColour(const QString& band) {
    if (band == QLatin1String("critical")) {
        return QColor(0xc0, 0x39, 0x2b); // red
    }
    if (band == QLatin1String("high")) {
        return QColor(0xe0, 0x6a, 0x0a); // orange
    }
    if (band == QLatin1String("medium")) {
        return QColor(0xd4, 0xa0, 0x17); // amber
    }
    return {}; // low / informational: leave the theme default
}

// A right-aligned, non-editable cell carrying a sort value, so columns of
// numbers (risk, CVSS, EPSS) order numerically rather than lexically.
QTableWidgetItem* numericItem(const QString& text, double sortKey) {
    auto* item = new QTableWidgetItem(text);
    item->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
    item->setData(Qt::UserRole, sortKey);
    return item;
}
} // namespace

RiskDialog::RiskDialog(PontusClient* client, QWidget* parent)
    : QDialog(parent), client_(client) {
    setWindowTitle(QStringLiteral("Risk — vulnerability triage queue"));
    resize(880, 600);

    scan_ = new QComboBox;
    connect(scan_, &QComboBox::currentIndexChanged, this, &RiskDialog::recompute);

    auto* selectors = new QHBoxLayout;
    selectors->addWidget(new QLabel(QStringLiteral("Scan")));
    selectors->addWidget(scan_, 1);

    hosts_ = new QTableWidget;
    hosts_->setColumnCount(5);
    hosts_->setHorizontalHeaderLabels({"Risk", "Identity", "IP", "Vulns", "Top finding"});
    hosts_->verticalHeader()->setVisible(false);
    hosts_->horizontalHeader()->setStretchLastSection(true);
    hosts_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    hosts_->setSelectionBehavior(QAbstractItemView::SelectRows);
    hosts_->setSelectionMode(QAbstractItemView::SingleSelection);
    connect(hosts_, &QTableWidget::itemSelectionChanged, this, &RiskDialog::onHostSelected);

    vulns_ = new QTableWidget;
    vulns_->setColumnCount(6);
    vulns_->setHorizontalHeaderLabels({"CVE", "Band", "CVSS", "EPSS", "KEV", "Match"});
    vulns_->verticalHeader()->setVisible(false);
    vulns_->horizontalHeader()->setStretchLastSection(true);
    vulns_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    vulns_->setSelectionMode(QAbstractItemView::NoSelection);
    // Double-click a CVE row to open its NVD detail page in the default browser.
    connect(vulns_, &QTableWidget::itemDoubleClicked, this, [](QTableWidgetItem* item) {
        if (!item) {
            return;
        }
        const QString cve = item->tableWidget()->item(item->row(), 0)->text();
        if (cve.startsWith(QLatin1String("CVE-"))) {
            QDesktopServices::openUrl(
                QUrl(QStringLiteral("https://nvd.nist.gov/vuln/detail/%1").arg(cve)));
        }
    });

    auto* hostsBox = new QWidget;
    auto* hostsLayout = new QVBoxLayout(hostsBox);
    hostsLayout->setContentsMargins(0, 0, 0, 0);
    auto* hostsLabel = new QLabel(QStringLiteral("Hosts — worst first"));
    hostsLayout->addWidget(hostsLabel);
    hostsLayout->addWidget(hosts_, 1);

    auto* vulnsBox = new QWidget;
    auto* vulnsLayout = new QVBoxLayout(vulnsBox);
    vulnsLayout->setContentsMargins(0, 0, 0, 0);
    auto* vulnsLabel = new QLabel(QStringLiteral("Selected host — vulnerabilities, worst first"));
    vulnsLayout->addWidget(vulnsLabel);
    vulnsLayout->addWidget(vulns_, 1);

    auto* splitter = new QSplitter(Qt::Vertical);
    splitter->addWidget(hostsBox);
    splitter->addWidget(vulnsBox);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);

    summary_ = new QLabel;
    applyMutedText(summary_);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::accept);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(selectors);
    layout->addWidget(splitter, 1);
    layout->addWidget(summary_);
    layout->addWidget(buttons);

    populateScans();
    recompute();
}

void RiskDialog::populateScans() {
    const QJsonArray scans = client_->scans(100); // newest first
    scan_->blockSignals(true);
    for (const QJsonValue& v : scans) {
        const QJsonObject s = v.toObject();
        const qlonglong id = s.value("id").toInt();
        scan_->addItem(
            QStringLiteral("scan %1 — %2").arg(id).arg(s.value("started_at").toString()), id);
    }
    if (!scans.isEmpty()) {
        scan_->setCurrentIndex(0); // newest
    }
    scan_->blockSignals(false);
}

void RiskDialog::recompute() {
    hosts_->setSortingEnabled(false);
    hosts_->setRowCount(0);
    vulns_->setRowCount(0);
    if (scan_->count() == 0) {
        summary_->setText(QStringLiteral("No scans yet — run a scan with --assess-vulns."));
        return;
    }

    const qlonglong scanId = scan_->currentData().toLongLong();
    ranked_ = client_->risk(scanId);
    if (ranked_.isEmpty()) {
        summary_->setText(QStringLiteral(
            "No vulnerabilities recorded for this scan. Re-run it with --assess-vulns "
            "(and `pontus-cli intel update` for KEV enrichment)."));
        return;
    }

    int kevHosts = 0, totalVulns = 0;
    for (int i = 0; i < ranked_.size(); ++i) {
        const QJsonObject h = ranked_.at(i).toObject();
        const QJsonArray vulns = h.value("vulns").toArray();
        totalVulns += vulns.size();
        const QJsonObject top = vulns.isEmpty() ? QJsonObject{} : vulns.first().toObject();
        const QString topBand = top.value("band").toString();
        const bool topKev = top.value("kev").toBool();
        if (topKev) {
            ++kevHosts;
        }

        const int row = hosts_->rowCount();
        hosts_->insertRow(row);

        const double risk = h.value("risk").toDouble();
        auto* riskItem = numericItem(QString::number(risk, 'f', 1), risk);
        // Stash the host index so the detail pane can find this host's vulns.
        riskItem->setData(Qt::UserRole + 1, i);

        auto* identityItem = new QTableWidgetItem(
            QStringLiteral("%1 %2").arg(h.value("identity_kind").toString(),
                                        h.value("identity_value").toString()));
        const QJsonValue ip = h.value("ip");
        auto* ipItem = new QTableWidgetItem(ip.isNull() ? QStringLiteral("-") : ip.toString());
        auto* countItem = numericItem(QString::number(vulns.size()), vulns.size());
        QString topText = top.value("cve_id").toString();
        if (topKev) {
            topText += QStringLiteral("  ⚠ KEV");
        }
        auto* topItem = new QTableWidgetItem(topText);

        const QColor colour = bandColour(topBand);
        if (colour.isValid()) {
            riskItem->setForeground(colour);
            topItem->setForeground(colour);
        }
        hosts_->setItem(row, 0, riskItem);
        hosts_->setItem(row, 1, identityItem);
        hosts_->setItem(row, 2, ipItem);
        hosts_->setItem(row, 3, countItem);
        hosts_->setItem(row, 4, topItem);
    }

    hosts_->resizeColumnsToContents();
    hosts_->horizontalHeader()->setStretchLastSection(true);
    if (hosts_->rowCount() > 0) {
        hosts_->selectRow(0); // drives onHostSelected → fills the detail pane
    }

    summary_->setText(QStringLiteral("%1 host(s) at risk · %2 KEV-listed · %3 vulnerabilit%4 total")
                          .arg(ranked_.size())
                          .arg(kevHosts)
                          .arg(totalVulns)
                          .arg(totalVulns == 1 ? QStringLiteral("y") : QStringLiteral("ies")));
}

void RiskDialog::onHostSelected() {
    vulns_->setSortingEnabled(false);
    vulns_->setRowCount(0);
    const QList<QTableWidgetItem*> selected = hosts_->selectedItems();
    if (selected.isEmpty()) {
        return;
    }
    const int hostIndex = hosts_->item(selected.first()->row(), 0)->data(Qt::UserRole + 1).toInt();
    if (hostIndex < 0 || hostIndex >= ranked_.size()) {
        return;
    }

    const QJsonArray vulns = ranked_.at(hostIndex).toObject().value("vulns").toArray();
    for (const QJsonValue& v : vulns) {
        const QJsonObject vuln = v.toObject();
        const int row = vulns_->rowCount();
        vulns_->insertRow(row);

        const QString band = vuln.value("band").toString();
        const QColor colour = bandColour(band);

        auto* cveItem = new QTableWidgetItem(vuln.value("cve_id").toString());
        cveItem->setToolTip(QStringLiteral("Double-click to open this CVE on NVD"));
        QFont linkFont = cveItem->font();
        linkFont.setUnderline(true);
        cveItem->setFont(linkFont);
        auto* bandItem = new QTableWidgetItem(band);

        const QJsonValue cvss = vuln.value("cvss");
        auto* cvssItem = cvss.isNull()
                             ? numericItem(QStringLiteral("-"), -1.0)
                             : numericItem(QString::number(cvss.toDouble(), 'f', 1), cvss.toDouble());

        const QJsonValue epss = vuln.value("epss");
        // EPSS is a probability in [0,1]; show it as a percentage, which reads as
        // "chance of exploitation in the next 30 days".
        auto* epssItem =
            epss.isNull()
                ? numericItem(QStringLiteral("-"), -1.0)
                : numericItem(QStringLiteral("%1%").arg(epss.toDouble() * 100.0, 0, 'f', 1),
                              epss.toDouble());

        const bool kev = vuln.value("kev").toBool();
        auto* kevItem = new QTableWidgetItem(kev ? QStringLiteral("● KEV") : QString());
        kevItem->setTextAlignment(Qt::AlignCenter);

        // Version-less matches are product-wide (every CVE for the product) and so
        // lower-confidence; mark them rather than suppress (IMP-003).
        const bool versionMatched = vuln.value("version_matched").toBool();
        auto* matchItem = new QTableWidgetItem(versionMatched ? QStringLiteral("exact")
                                                              : QStringLiteral("product-wide"));
        if (!versionMatched) {
            matchItem->setForeground(bandColour(QStringLiteral("medium")));
            matchItem->setToolTip(QStringLiteral(
                "No version was detected, so this matches every CVE for the product — "
                "likely over-reports."));
        }

        if (colour.isValid()) {
            cveItem->setForeground(colour);
            bandItem->setForeground(colour);
        }
        if (kev) {
            kevItem->setForeground(bandColour(QStringLiteral("critical")));
        }
        vulns_->setItem(row, 0, cveItem);
        vulns_->setItem(row, 1, bandItem);
        vulns_->setItem(row, 2, cvssItem);
        vulns_->setItem(row, 3, epssItem);
        vulns_->setItem(row, 4, kevItem);
        vulns_->setItem(row, 5, matchItem);
    }
    vulns_->resizeColumnsToContents();
    vulns_->horizontalHeader()->setStretchLastSection(true);
}
