#include "heatmapdialog.h"

#include "pontusclient.h"
#include "uiutil.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QMap>
#include <QPair>
#include <QSet>
#include <QStringList>
#include <QTableWidget>
#include <QVBoxLayout>

#include <algorithm>

HeatmapDialog::HeatmapDialog(PontusClient* client, QWidget* parent)
    : QDialog(parent), client_(client) {
    setWindowTitle(QStringLiteral("Service / port heatmap"));
    resize(900, 600);

    auto* note = new QLabel(QStringLiteral(
        "Open services for one scan — every host compared on the same port coverage. "
        "Columns are ordered most-shared first; vertical bands are shared exposure. "
        "Green = confirmed open; amber = UDP open|filtered (no reply — unconfirmed)."));
    note->setWordWrap(true);
    applyMutedText(note);

    scan_ = new QComboBox;
    connect(scan_, &QComboBox::currentIndexChanged, this, &HeatmapDialog::build);
    auto* selectors = new QHBoxLayout;
    selectors->addWidget(new QLabel(QStringLiteral("Scan")));
    selectors->addWidget(scan_, 1);

    table_ = new QTableWidget;
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->setSelectionMode(QAbstractItemView::NoSelection);
    table_->verticalHeader()->setVisible(false);

    summary_ = new QLabel;

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::accept);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(note);
    layout->addLayout(selectors);
    layout->addWidget(table_, 1);
    layout->addWidget(summary_);
    layout->addWidget(buttons);

    populateScans();
    build();
}

void HeatmapDialog::populateScans() {
    scan_->blockSignals(true);
    for (const QJsonValue& v : client_->scans(100)) { // newest first
        const QJsonObject s = v.toObject();
        const qlonglong id = s.value("id").toInt();
        scan_->addItem(
            QStringLiteral("scan %1 — %2").arg(id).arg(s.value("started_at").toString()), id);
    }
    scan_->setCurrentIndex(0); // latest
    scan_->blockSignals(false);
}

void HeatmapDialog::build() {
    // Gather open ports per host from a single scan, so every host is measured
    // against the same port coverage (not each host's latest observation, which
    // mixes scans with different port sets).
    // (host label, port "proto/port" -> confirmed?). A UDP port is "confirmed"
    // only if the host actually replied; "open|filtered" means no reply, so it is
    // shown distinctly rather than as a solid open service (IMP-016).
    QList<QPair<QString, QMap<QString, bool>>> rows;
    QMap<QString, int> counts; // port -> number of hosts exposing it

    if (scan_->count() == 0) {
        table_->clear();
        table_->setRowCount(0);
        table_->setColumnCount(1);
        table_->setHorizontalHeaderLabels({QStringLiteral("Host")});
        summary_->setText(QStringLiteral("No scans yet."));
        return;
    }
    const qlonglong scanId = scan_->currentData().toLongLong();

    for (const QJsonValue& v : client_->observations(scanId)) {
        const QJsonObject o = v.toObject();
        const QString host = o.value("identity_value").toString();
        const QString ip = o.value("ip").toString();
        const QString label = ip.isEmpty() ? host : QStringLiteral("%1 (%2)").arg(host, ip);

        QMap<QString, bool> ports;
        const QJsonObject state = o.value("state").toObject();
        for (const QJsonValue& pv : state.value("open_ports").toArray()) {
            const QJsonObject p = pv.toObject();
            const QString proto = p.value("proto").toString();
            const QString key = QStringLiteral("%1/%2").arg(proto).arg(p.value("port").toInt());
            // UDP with no reply is recorded as service "open|filtered" — unconfirmed.
            const bool confirmed = !(proto == QLatin1String("udp")
                                     && p.value("service").toString() == QLatin1String("open|filtered"));
            ports.insert(key, confirmed);
        }
        rows.append({label, ports});
        for (auto it = ports.constBegin(); it != ports.constEnd(); ++it) {
            ++counts[it.key()];
        }
    }

    // Columns: open ports, most-shared first (then by name).
    QStringList columns = counts.keys();
    std::sort(columns.begin(), columns.end(), [&counts](const QString& a, const QString& b) {
        if (counts[a] != counts[b]) {
            return counts[a] > counts[b];
        }
        return a < b;
    });

    table_->clear();
    table_->setColumnCount(columns.size() + 1);
    table_->setRowCount(rows.size());
    QStringList headers;
    headers << QStringLiteral("Host");
    for (const QString& column : columns) {
        headers << QStringLiteral("%1 ·%2").arg(column).arg(counts[column]);
    }
    table_->setHorizontalHeaderLabels(headers);

    const QColor openColour(0x27, 0xae, 0x60);     // confirmed open (green)
    const QColor maybeColour(0xb7, 0x83, 0x0a);    // open|filtered — no reply (amber)
    for (int r = 0; r < rows.size(); ++r) {
        table_->setItem(r, 0, new QTableWidgetItem(rows[r].first));
        for (int c = 0; c < columns.size(); ++c) {
            auto* cell = new QTableWidgetItem;
            const auto it = rows[r].second.constFind(columns[c]);
            if (it != rows[r].second.constEnd()) {
                const bool confirmed = it.value();
                cell->setBackground(confirmed ? openColour : maybeColour);
                cell->setToolTip(QStringLiteral("%1 %2 on %3")
                                     .arg(columns[c],
                                          confirmed ? QStringLiteral("open")
                                                    : QStringLiteral("open|filtered (no reply)"),
                                          rows[r].first));
            }
            table_->setItem(r, c + 1, cell);
        }
    }
    table_->resizeColumnsToContents();
    table_->horizontalHeader()->setStretchLastSection(true);
    summary_->setText(
        QStringLiteral("%1 host(s) × %2 service(s)").arg(rows.size()).arg(columns.size()));
}
