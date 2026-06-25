#include "topologydialog.h"

#include "pontusclient.h"
#include "topologyview.h"

#include <QComboBox>
#include <QDialogButtonBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QVBoxLayout>

TopologyDialog::TopologyDialog(PontusClient* client, QWidget* parent)
    : QDialog(parent), client_(client) {
    setWindowTitle(QStringLiteral("Topology"));
    resize(840, 640);

    scan_ = new QComboBox;
    view_ = new TopologyView;

    auto* note = new QLabel(QStringLiteral(
        "Traceroute paths (F-009). Drag to pan, scroll to zoom; the scanner is "
        "pinned at the centre."));
    note->setWordWrap(true);

    // Populate scans (newest first); default to the newest that actually has
    // topology data, so the graph isn't empty on open.
    const QJsonArray scans = client_->scans(100);
    int defaultIndex = 0;
    bool found = false;
    for (int i = 0; i < scans.size(); ++i) {
        const QJsonObject s = scans.at(i).toObject();
        const qlonglong id = s.value(QStringLiteral("id")).toInt();
        scan_->addItem(
            QStringLiteral("scan %1 — %2").arg(id).arg(s.value(QStringLiteral("started_at")).toString()),
            id);
        if (!found && !client_->topology(id).isEmpty()) {
            defaultIndex = i;
            found = true;
        }
    }
    connect(scan_, &QComboBox::currentIndexChanged, this, &TopologyDialog::onScanChanged);

    auto* top = new QHBoxLayout;
    top->addWidget(new QLabel(QStringLiteral("Scan")));
    top->addWidget(scan_, 1);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::accept);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(note);
    layout->addLayout(top);
    layout->addWidget(view_, 1);
    layout->addWidget(buttons);

    if (scan_->count() > 0) {
        scan_->blockSignals(true);
        scan_->setCurrentIndex(defaultIndex);
        scan_->blockSignals(false);
        onScanChanged();
    }
}

void TopologyDialog::onScanChanged() {
    if (scan_->count() == 0) {
        return;
    }
    const qlonglong id = scan_->currentData().toLongLong();
    view_->setTopology(client_->topology(id));
}
