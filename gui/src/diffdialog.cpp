#include "diffdialog.h"

#include "pontusclient.h"

#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QVBoxLayout>

namespace {
// Render a PortRef array as signed "proto/port" tokens, e.g. "+tcp/8080".
QString signedPorts(const QJsonArray& ports, QChar sign) {
    QStringList parts;
    for (const QJsonValue& v : ports) {
        const QJsonObject p = v.toObject();
        parts << QStringLiteral("%1%2/%3").arg(sign)
                     .arg(p.value("proto").toString())
                     .arg(p.value("port").toInt());
    }
    return parts.join(QStringLiteral("  "));
}

// Colour for a host status; invalid (default colour) for Unchanged.
QColor statusColour(const QString& status) {
    if (status == QLatin1String("New")) {
        return QColor(0x27, 0xae, 0x60); // green
    }
    if (status == QLatin1String("Vanished")) {
        return QColor(0xc0, 0x39, 0x2b); // red
    }
    if (status == QLatin1String("Changed")) {
        return QColor(0xe0, 0x8e, 0x0a); // amber
    }
    return {};
}
} // namespace

DiffDialog::DiffDialog(PontusClient* client, QWidget* parent)
    : QDialog(parent), client_(client) {
    setWindowTitle(QStringLiteral("Drift — compare two scans"));
    resize(860, 560);

    from_ = new QComboBox;
    to_ = new QComboBox;
    showUnchanged_ = new QCheckBox(QStringLiteral("Show unchanged"));
    connect(from_, &QComboBox::currentIndexChanged, this, &DiffDialog::recompute);
    connect(to_, &QComboBox::currentIndexChanged, this, &DiffDialog::recompute);
    connect(showUnchanged_, &QCheckBox::toggled, this, &DiffDialog::recompute);

    auto* setBaseline = new QPushButton(QStringLiteral("Set From as baseline"));
    setBaseline->setToolTip(QStringLiteral("Designate the From scan as the baseline to diff against (F-014)"));
    connect(setBaseline, &QPushButton::clicked, this, &DiffDialog::onSetBaseline);
    baselineLabel_ = new QLabel;

    auto* selectors = new QHBoxLayout;
    selectors->addWidget(new QLabel(QStringLiteral("From")));
    selectors->addWidget(from_, 1);
    selectors->addWidget(new QLabel(QStringLiteral("→  To")));
    selectors->addWidget(to_, 1);
    selectors->addWidget(showUnchanged_);

    auto* baselineRow = new QHBoxLayout;
    baselineRow->addWidget(setBaseline);
    baselineRow->addWidget(baselineLabel_, 1);

    table_ = new QTableWidget;
    table_->setColumnCount(4);
    table_->setHorizontalHeaderLabels({"Status", "Identity", "IP", "Changes"});
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionMode(QAbstractItemView::NoSelection);

    summary_ = new QLabel;

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::accept);

    auto* layout = new QVBoxLayout(this);
    layout->addLayout(selectors);
    layout->addLayout(baselineRow);
    layout->addWidget(table_, 1);
    layout->addWidget(summary_);
    layout->addWidget(buttons);

    populateScans();
    updateBaselineLabel();
    recompute();
}

void DiffDialog::populateScans() {
    const QJsonArray scans = client_->scans(100); // newest first
    from_->blockSignals(true);
    to_->blockSignals(true);
    for (const QJsonValue& v : scans) {
        const QJsonObject s = v.toObject();
        const qlonglong id = s.value("id").toInt();
        const QString label =
            QStringLiteral("scan %1 — %2").arg(id).arg(s.value("started_at").toString());
        from_->addItem(label, id);
        to_->addItem(label, id);
    }
    // Default From to the designated baseline if one exists and is present,
    // otherwise the second-newest scan; To is always the newest.
    if (!scans.isEmpty()) {
        to_->setCurrentIndex(0);
        const long long baseline = client_->baseline();
        int fromIndex = scans.size() >= 2 ? 1 : 0;
        if (baseline >= 0) {
            const int found = from_->findData(static_cast<qlonglong>(baseline));
            if (found >= 0) {
                fromIndex = found;
            }
        }
        from_->setCurrentIndex(fromIndex);
    }
    from_->blockSignals(false);
    to_->blockSignals(false);
}

void DiffDialog::onSetBaseline() {
    if (from_->count() == 0) {
        return;
    }
    const qlonglong scanId = from_->currentData().toLongLong();
    client_->setBaseline(scanId);
    updateBaselineLabel();
}

void DiffDialog::updateBaselineLabel() {
    const long long baseline = client_->baseline();
    baselineLabel_->setText(baseline >= 0
                                ? QStringLiteral("Baseline: scan %1").arg(baseline)
                                : QStringLiteral("Baseline: none set"));
}

void DiffDialog::recompute() {
    table_->setRowCount(0);
    if (from_->count() == 0 || to_->count() == 0) {
        summary_->setText(QStringLiteral("Need at least two scans to compare."));
        return;
    }

    const qlonglong fromId = from_->currentData().toLongLong();
    const qlonglong toId = to_->currentData().toLongLong();
    const QJsonArray diffs = client_->diff(fromId, toId);
    const bool showUnchanged = showUnchanged_->isChecked();

    int created = 0, vanished = 0, changed = 0, unchanged = 0;
    for (const QJsonValue& v : diffs) {
        const QJsonObject d = v.toObject();
        const QString status = d.value("status").toString();
        if (status == QLatin1String("New")) {
            ++created;
        } else if (status == QLatin1String("Vanished")) {
            ++vanished;
        } else if (status == QLatin1String("Changed")) {
            ++changed;
        } else {
            ++unchanged;
            if (!showUnchanged) {
                continue;
            }
        }

        QStringList changes;
        const QJsonValue movedFrom = d.value("moved_from");
        if (!movedFrom.isNull()) {
            changes << QStringLiteral("moved %1 → %2").arg(movedFrom.toString(),
                                                           d.value("ip").toString());
        }
        const QString opened = signedPorts(d.value("opened").toArray(), QLatin1Char('+'));
        const QString closed = signedPorts(d.value("closed").toArray(), QLatin1Char('-'));
        if (!opened.isEmpty()) {
            changes << opened;
        }
        if (!closed.isEmpty()) {
            changes << closed;
        }

        const int row = table_->rowCount();
        table_->insertRow(row);
        const QColor colour = statusColour(status);

        auto* statusItem = new QTableWidgetItem(status);
        auto* identityItem = new QTableWidgetItem(
            QStringLiteral("%1 %2").arg(d.value("identity_kind").toString(),
                                        d.value("identity_value").toString()));
        auto* ipItem = new QTableWidgetItem(d.value("ip").toString());
        auto* changesItem = new QTableWidgetItem(changes.join(QStringLiteral("    ")));
        if (colour.isValid()) {
            statusItem->setForeground(colour);
            changesItem->setForeground(colour);
        }
        table_->setItem(row, 0, statusItem);
        table_->setItem(row, 1, identityItem);
        table_->setItem(row, 2, ipItem);
        table_->setItem(row, 3, changesItem);
    }

    table_->resizeColumnsToContents();
    table_->horizontalHeader()->setStretchLastSection(true);
    summary_->setText(QStringLiteral("%1 new · %2 vanished · %3 changed · %4 unchanged")
                          .arg(created)
                          .arg(vanished)
                          .arg(changed)
                          .arg(unchanged));
}
