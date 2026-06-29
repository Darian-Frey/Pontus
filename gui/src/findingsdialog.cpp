#include "findingsdialog.h"

#include "pontusclient.h"
#include "uiutil.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {
// Colour and rank by severity. Rank doubles as the sort key so the Severity
// column orders worst-first. Low/info keep the theme default (muted tail).
QColor severityColour(const QString& severity) {
    if (severity == QLatin1String("critical")) {
        return QColor(0xc0, 0x39, 0x2b); // red
    }
    if (severity == QLatin1String("high")) {
        return QColor(0xe0, 0x6a, 0x0a); // orange
    }
    if (severity == QLatin1String("medium")) {
        return QColor(0xd4, 0xa0, 0x17); // amber
    }
    return {}; // low / info
}

int severityRank(const QString& severity) {
    if (severity == QLatin1String("critical")) return 4;
    if (severity == QLatin1String("high")) return 3;
    if (severity == QLatin1String("medium")) return 2;
    if (severity == QLatin1String("low")) return 1;
    return 0; // info / unknown
}

// Sorts by severity rank (stashed in UserRole) rather than the label text, so the
// Severity column orders critical→info instead of alphabetically.
class SeverityItem : public QTableWidgetItem {
public:
    explicit SeverityItem(const QString& text) : QTableWidgetItem(text) {}
    bool operator<(const QTableWidgetItem& other) const override {
        return data(Qt::UserRole).toInt() < other.data(Qt::UserRole).toInt();
    }
};
} // namespace

FindingsDialog::FindingsDialog(PontusClient* client, QWidget* parent)
    : QDialog(parent), client_(client) {
    setWindowTitle(QStringLiteral("Findings — plugin results"));
    resize(900, 560);

    scan_ = new QComboBox;
    connect(scan_, &QComboBox::currentIndexChanged, this, &FindingsDialog::recompute);
    auto* selectors = new QHBoxLayout;
    selectors->addWidget(new QLabel(QStringLiteral("Scan")));
    selectors->addWidget(scan_, 1);

    table_ = new QTableWidget;
    table_->setColumnCount(5);
    table_->setHorizontalHeaderLabels({"Severity", "Host", "Plugin", "Title", "Description"});
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);

    summary_ = new QLabel;
    applyMutedText(summary_);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::accept);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(selectors);
    layout->addWidget(table_, 1);
    layout->addWidget(summary_);
    layout->addWidget(buttons);

    populateScans();
    recompute();
}

void FindingsDialog::populateScans() {
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

void FindingsDialog::recompute() {
    table_->setSortingEnabled(false);
    table_->setRowCount(0);
    if (scan_->count() == 0) {
        summary_->setText(QStringLiteral("No scans yet — run a scan with a plugins directory set."));
        return;
    }

    const qlonglong scanId = scan_->currentData().toLongLong();
    const QJsonArray findings = client_->findings(scanId);
    if (findings.isEmpty()) {
        summary_->setText(QStringLiteral(
            "No plugin findings for this scan. Re-run it with a plugins directory "
            "(New scan… ▸ Plugins, or `pontus-cli scan --plugins <dir>`)."));
        return;
    }

    for (const QJsonValue& v : findings) {
        const QJsonObject f = v.toObject();
        const int row = table_->rowCount();
        table_->insertRow(row);

        const QString severity = f.value("severity").toString();
        const QJsonValue ipv = f.value("ip");
        const QString host = ipv.isNull() || ipv.toString().isEmpty()
                                 ? f.value("identity").toString()
                                 : ipv.toString();

        auto* sevItem = new SeverityItem(severity);
        sevItem->setData(Qt::UserRole, severityRank(severity)); // numeric sort key
        auto* hostItem = new QTableWidgetItem(host);
        auto* pluginItem = new QTableWidgetItem(f.value("plugin").toString());
        auto* titleItem = new QTableWidgetItem(f.value("title").toString());
        const QString description = f.value("description").toString();
        auto* descItem = new QTableWidgetItem(description);
        descItem->setToolTip(description);

        const QColor colour = severityColour(severity);
        if (colour.isValid()) {
            sevItem->setForeground(colour);
            titleItem->setForeground(colour);
        }

        table_->setItem(row, 0, sevItem);
        table_->setItem(row, 1, hostItem);
        table_->setItem(row, 2, pluginItem);
        table_->setItem(row, 3, titleItem);
        table_->setItem(row, 4, descItem);
    }

    table_->resizeColumnsToContents();
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setSortingEnabled(true);
    table_->sortItems(0, Qt::DescendingOrder); // worst severity first

    summary_->setText(QStringLiteral("%1 finding(s) across this scan")
                          .arg(findings.size()));
}
