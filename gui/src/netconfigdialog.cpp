#include "netconfigdialog.h"

#include "pontusclient.h"

#include <QDialogButtonBox>
#include <QHeaderView>
#include <QJsonArray>
#include <QJsonObject>
#include <QLabel>
#include <QStringList>
#include <QTableWidget>
#include <QVBoxLayout>

NetConfigDialog::NetConfigDialog(PontusClient* client, QWidget* parent)
    : QDialog(parent), client_(client) {
    setWindowTitle(QStringLiteral("Local network configuration"));
    resize(720, 600);

    interfaces_ = new QTableWidget;
    interfaces_->setColumnCount(6);
    interfaces_->setHorizontalHeaderLabels({"Interface", "MAC", "Address", "Prefix", "Netmask", "Flags"});
    interfaces_->verticalHeader()->setVisible(false);
    interfaces_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    interfaces_->setSelectionMode(QAbstractItemView::NoSelection);

    listening_ = new QTableWidget;
    listening_->setColumnCount(3);
    listening_->setHorizontalHeaderLabels({"Proto", "Address", "Port"});
    listening_->verticalHeader()->setVisible(false);
    listening_->horizontalHeader()->setStretchLastSection(true);
    listening_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    listening_->setSelectionMode(QAbstractItemView::NoSelection);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::accept);

    auto* layout = new QVBoxLayout(this);
    layout->addWidget(new QLabel(QStringLiteral("Interfaces")));
    layout->addWidget(interfaces_, 3);
    layout->addWidget(new QLabel(QStringLiteral("Listening ports (this machine's exposed services)")));
    layout->addWidget(listening_, 2);
    layout->addWidget(buttons);

    build();
}

void NetConfigDialog::build() {
    const QJsonObject cfg = client_->localConfig();

    // Interfaces — one row per bound address (an interface with none gets one row).
    const QJsonArray ifaces = cfg.value(QStringLiteral("interfaces")).toArray();
    interfaces_->setRowCount(0);
    for (const QJsonValue& v : ifaces) {
        const QJsonObject i = v.toObject();
        const QString name = i.value("name").toString();
        const QString mac = i.value("mac").isNull() ? QStringLiteral("-") : i.value("mac").toString();
        QStringList flags;
        flags << (i.value("up").toBool() ? QStringLiteral("up") : QStringLiteral("down"));
        if (i.value("loopback").toBool()) {
            flags << QStringLiteral("loopback");
        }
        const QJsonArray addrs = i.value("addrs").toArray();
        if (addrs.isEmpty()) {
            const int r = interfaces_->rowCount();
            interfaces_->insertRow(r);
            interfaces_->setItem(r, 0, new QTableWidgetItem(name));
            interfaces_->setItem(r, 1, new QTableWidgetItem(mac));
            interfaces_->setItem(r, 5, new QTableWidgetItem(flags.join(QStringLiteral(", "))));
            continue;
        }
        for (const QJsonValue& av : addrs) {
            const QJsonObject a = av.toObject();
            const int r = interfaces_->rowCount();
            interfaces_->insertRow(r);
            interfaces_->setItem(r, 0, new QTableWidgetItem(name));
            interfaces_->setItem(r, 1, new QTableWidgetItem(mac));
            interfaces_->setItem(r, 2, new QTableWidgetItem(a.value("ip").toString()));
            interfaces_->setItem(r, 3, new QTableWidgetItem(QStringLiteral("/%1").arg(a.value("prefix").toInt())));
            interfaces_->setItem(r, 4, new QTableWidgetItem(a.value("netmask").isNull()
                                                                ? QStringLiteral("-")
                                                                : a.value("netmask").toString()));
            interfaces_->setItem(r, 5, new QTableWidgetItem(flags.join(QStringLiteral(", "))));
        }
    }
    interfaces_->resizeColumnsToContents();
    interfaces_->horizontalHeader()->setStretchLastSection(true);

    // Listening ports.
    const QJsonArray ports = cfg.value(QStringLiteral("listening")).toArray();
    listening_->setRowCount(ports.size());
    for (int r = 0; r < ports.size(); ++r) {
        const QJsonObject p = ports.at(r).toObject();
        listening_->setItem(r, 0, new QTableWidgetItem(p.value("proto").toString()));
        listening_->setItem(r, 1, new QTableWidgetItem(p.value("address").toString()));
        listening_->setItem(r, 2, new QTableWidgetItem(QString::number(p.value("port").toInt())));
    }
    listening_->resizeColumnsToContents();
    listening_->horizontalHeader()->setStretchLastSection(true);
}
