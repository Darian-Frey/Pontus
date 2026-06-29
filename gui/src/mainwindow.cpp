#include "mainwindow.h"
#include "diffdialog.h"
#include "findingsdialog.h"
#include "heatmapdialog.h"
#include "netconfigdialog.h"
#include "riskdialog.h"
#include "scandialog.h"
#include "topologydialog.h"

#include <QAction>
#include <QCoreApplication>
#include <QDateTime>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QStandardPaths>
#include <QGroupBox>
#include <QHeaderView>
#include <QItemSelectionModel>
#include <QJsonArray>
#include <QJsonObject>
#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMenuBar>
#include <QSortFilterProxyModel>
#include <QSplitter>
#include <QStandardItemModel>
#include <QStatusBar>
#include <QStringList>
#include <QTableView>
#include <QTableWidget>
#include <QTextEdit>
#include <QVBoxLayout>

namespace {
const QStringList kColumns = {"ID", "Anchor", "Identity", "Hostname", "Last IP", "MAC", "OS", "Obs", "Last seen"};

// Render an observation's open ports as "proto/port" tokens.
QString portsSummary(const QJsonObject& state) {
    QStringList parts;
    for (const QJsonValue& v : state.value("open_ports").toArray()) {
        const QJsonObject p = v.toObject();
        parts << QStringLiteral("%1/%2").arg(p.value("proto").toString(),
                                             QString::number(p.value("port").toInt()));
    }
    return parts.isEmpty() ? QStringLiteral("-") : parts.join(", ");
}

// Render the TLS/web deep-inspection findings (F-016/F-017) recorded on an
// observation's ports, for the detail pane.
QString inspectionText(const QJsonObject& state) {
    QStringList lines;
    for (const QJsonValue& v : state.value("open_ports").toArray()) {
        const QJsonObject p = v.toObject();
        const int port = p.value("port").toInt();
        const QJsonObject tls = p.value("tls").toObject();
        if (!tls.isEmpty()) {
            QStringList protos;
            for (const QJsonValue& pv : tls.value("protocols").toArray()) {
                protos << pv.toString();
            }
            lines << QStringLiteral("TLS :%1  %2").arg(port).arg(protos.join(", "));
            QStringList weak;
            for (const QJsonValue& wv : tls.value("weak_ciphers").toArray()) {
                weak << wv.toString();
            }
            if (!weak.isEmpty()) {
                lines << QStringLiteral("    weak ciphers: %1").arg(weak.join(", "));
            }
            const QString subj = tls.value("cert_subject").toString();
            if (!subj.isEmpty()) {
                lines << QStringLiteral("    cert: %1").arg(subj);
            }
            const QJsonValue notAfter = tls.value("cert_not_after");
            if (notAfter.isDouble()) {
                const QDateTime exp = QDateTime::fromSecsSinceEpoch(notAfter.toInteger(), Qt::UTC);
                lines << QStringLiteral("    expires: %1").arg(exp.toString(QStringLiteral("yyyy-MM-dd")));
            }
            for (const QJsonValue& fv : tls.value("findings").toArray()) {
                lines << QStringLiteral("    ! %1").arg(fv.toString());
            }
        }
        const QJsonArray tech = p.value("tech").toArray();
        if (!tech.isEmpty()) {
            QStringList names;
            for (const QJsonValue& tv : tech) {
                const QJsonObject t = tv.toObject();
                const QString name = t.value("name").toString();
                const QString ver = t.value("version").toString();
                names << (ver.isEmpty() ? name : QStringLiteral("%1 %2").arg(name, ver));
            }
            lines << QStringLiteral("Web :%1  %2").arg(port).arg(names.join(", "));
        }
    }
    return lines.join(QStringLiteral("\n"));
}

QString orDash(const QJsonValue& v) {
    return (v.isNull() || v.isUndefined()) ? QStringLiteral("-") : v.toString();
}

// A non-editable item whose sort key is numeric (for the ID / Obs columns).
QStandardItem* numericItem(int value) {
    auto* item = new QStandardItem;
    item->setData(value, Qt::DisplayRole);
    item->setEditable(false);
    return item;
}

QStandardItem* textItem(const QString& text) {
    auto* item = new QStandardItem(text);
    item->setEditable(false);
    return item;
}
} // namespace

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("Pontus — asset inventory"));
    resize(1100, 650);

    QMenu* fileMenu = menuBar()->addMenu(QStringLiteral("&File"));
    QAction* openAct = fileMenu->addAction(QStringLiteral("&Open database…"));
    openAct->setShortcut(QKeySequence::Open);
    connect(openAct, &QAction::triggered, this, &MainWindow::onOpen);
    QAction* refreshAct = fileMenu->addAction(QStringLiteral("&Refresh"));
    refreshAct->setShortcut(QKeySequence::Refresh);
    connect(refreshAct, &QAction::triggered, this, &MainWindow::onRefresh);
    fileMenu->addSeparator();
    QAction* quitAct = fileMenu->addAction(QStringLiteral("&Quit"));
    quitAct->setShortcut(QKeySequence::Quit);
    connect(quitAct, &QAction::triggered, this, &QWidget::close);

    QMenu* scanMenu = menuBar()->addMenu(QStringLiteral("&Scan"));
    QAction* newScanAct = scanMenu->addAction(QStringLiteral("&New scan…"));
    newScanAct->setShortcut(QKeySequence::New);
    connect(newScanAct, &QAction::triggered, this, &MainWindow::onNewScan);

    QMenu* viewMenu = menuBar()->addMenu(QStringLiteral("&View"));
    QAction* diffAct = viewMenu->addAction(QStringLiteral("&Drift / diff…"));
    diffAct->setShortcut(QKeySequence(QStringLiteral("Ctrl+D")));
    connect(diffAct, &QAction::triggered, this, &MainWindow::onDiff);
    QAction* heatmapAct = viewMenu->addAction(QStringLiteral("Service &heatmap…"));
    heatmapAct->setShortcut(QKeySequence(QStringLiteral("Ctrl+H")));
    connect(heatmapAct, &QAction::triggered, this, &MainWindow::onHeatmap);
    QAction* topologyAct = viewMenu->addAction(QStringLiteral("&Topology…"));
    topologyAct->setShortcut(QKeySequence(QStringLiteral("Ctrl+T")));
    connect(topologyAct, &QAction::triggered, this, &MainWindow::onTopology);
    QAction* riskAct = viewMenu->addAction(QStringLiteral("&Risk / vulnerabilities…"));
    riskAct->setShortcut(QKeySequence(QStringLiteral("Ctrl+R")));
    connect(riskAct, &QAction::triggered, this, &MainWindow::onRisk);
    QAction* findingsAct = viewMenu->addAction(QStringLiteral("Plugin &findings…"));
    findingsAct->setShortcut(QKeySequence(QStringLiteral("Ctrl+F")));
    connect(findingsAct, &QAction::triggered, this, &MainWindow::onFindings);
    QAction* netCfgAct = viewMenu->addAction(QStringLiteral("&Local network config…"));
    netCfgAct->setShortcut(QKeySequence(QStringLiteral("Ctrl+L")));
    connect(netCfgAct, &QAction::triggered, this, &MainWindow::onNetConfig);

    // Left: filter box over the asset table (the F-029 workhorse, first cut).
    filter_ = new QLineEdit;
    filter_->setPlaceholderText(QStringLiteral("Filter assets… (identity, hostname, IP)"));
    connect(filter_, &QLineEdit::textChanged, this, &MainWindow::onFilterChanged);

    model_ = new QStandardItemModel(this);
    model_->setHorizontalHeaderLabels(kColumns);
    proxy_ = new QSortFilterProxyModel(this);
    proxy_->setSourceModel(model_);
    proxy_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy_->setFilterKeyColumn(-1); // match against every column

    table_ = new QTableView;
    table_->setModel(proxy_);
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setSortingEnabled(true);
    table_->verticalHeader()->setVisible(false);
    table_->horizontalHeader()->setStretchLastSection(true);
    connect(table_->selectionModel(), &QItemSelectionModel::selectionChanged,
            this, &MainWindow::onSelectionChanged);

    auto* leftBox = new QWidget;
    auto* leftLayout = new QVBoxLayout(leftBox);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->addWidget(filter_);
    leftLayout->addWidget(table_);

    // Right: detail pane — selected asset's observation history.
    detailHeader_ = new QLabel(QStringLiteral("Select an asset"));
    detailHeader_->setStyleSheet(QStringLiteral("font-weight: bold;"));
    macLabel_ = new QLabel;
    macLabel_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    history_ = new QTableWidget;
    history_->setColumnCount(6);
    history_->setHorizontalHeaderLabels({"Observed at", "Scan", "IP", "Up", "OS", "Open ports"});
    history_->verticalHeader()->setVisible(false);
    history_->horizontalHeader()->setStretchLastSection(true);
    history_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    history_->setSelectionMode(QAbstractItemView::NoSelection);

    // Deep-inspection findings (TLS/web, F-016/F-017) for the latest observation.
    inspection_ = new QTextEdit;
    inspection_->setReadOnly(true);
    inspection_->setPlaceholderText(
        QStringLiteral("TLS / web findings for the latest observation (scan with --inspect)"));

    auto* rightBox = new QGroupBox(QStringLiteral("Asset detail"));
    auto* rightLayout = new QVBoxLayout(rightBox);
    rightLayout->addWidget(detailHeader_);
    rightLayout->addWidget(macLabel_);
    rightLayout->addWidget(history_, 3);
    rightLayout->addWidget(new QLabel(QStringLiteral("Deep inspection (latest)")));
    rightLayout->addWidget(inspection_, 1);

    auto* splitter = new QSplitter;
    splitter->addWidget(leftBox);
    splitter->addWidget(rightBox);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 2);
    setCentralWidget(splitter);

    statusBar()->showMessage(QStringLiteral("No database open — File ▸ Open database…"));
}

void MainWindow::openDatabase(const QString& path) {
    if (path.isEmpty()) {
        return;
    }
    if (!client_.open(path)) {
        statusBar()->showMessage(QStringLiteral("Failed to open %1").arg(path));
        return;
    }
    setWindowTitle(QStringLiteral("Pontus — %1").arg(path));
    reload();
}

void MainWindow::onOpen() {
    const QString path = QFileDialog::getOpenFileName(
        this, QStringLiteral("Open Pontus database"), QString(),
        QStringLiteral("Pontus store (*.db);;All files (*)"));
    openDatabase(path);
}

void MainWindow::onRefresh() {
    if (client_.isOpen()) {
        reload();
    }
}

void MainWindow::onNewScan() {
    const QString cli = findPontusCli();
    const QString defaultDb = client_.isOpen() ? client_.dbPath() : QStringLiteral("pontus.db");
    ScanDialog dialog(cli, defaultDb, this);
    dialog.exec();
    // If a scan completed, open/reload the store it wrote into.
    const QString scanned = dialog.scannedDatabase();
    if (!scanned.isEmpty()) {
        openDatabase(scanned);
    }
}

void MainWindow::onDiff() {
    if (!client_.isOpen()) {
        statusBar()->showMessage(QStringLiteral("Open a database first."));
        return;
    }
    DiffDialog dialog(&client_, this);
    dialog.exec();
}

void MainWindow::onHeatmap() {
    if (!client_.isOpen()) {
        statusBar()->showMessage(QStringLiteral("Open a database first."));
        return;
    }
    HeatmapDialog dialog(&client_, this);
    dialog.exec();
}

void MainWindow::onTopology() {
    if (!client_.isOpen()) {
        statusBar()->showMessage(QStringLiteral("Open a database first."));
        return;
    }
    TopologyDialog dialog(&client_, this);
    dialog.exec();
}

void MainWindow::onRisk() {
    if (!client_.isOpen()) {
        statusBar()->showMessage(QStringLiteral("Open a database first."));
        return;
    }
    RiskDialog dialog(&client_, this);
    dialog.exec();
}

void MainWindow::onFindings() {
    if (!client_.isOpen()) {
        statusBar()->showMessage(QStringLiteral("Open a database first."));
        return;
    }
    FindingsDialog dialog(&client_, this);
    dialog.exec();
}

void MainWindow::onNetConfig() {
    // Local config is "self" info — no store needed, so this works without an
    // open database.
    NetConfigDialog dialog(&client_, this);
    dialog.exec();
}

QString MainWindow::findPontusCli() const {
    const QString fromEnv = qEnvironmentVariable("PONTUS_CLI");
    if (!fromEnv.isEmpty() && QFileInfo(fromEnv).isExecutable()) {
        return fromEnv;
    }
    const QString appDir = QCoreApplication::applicationDirPath();
    const QStringList candidates = {
        appDir + QStringLiteral("/pontus-cli"),                          // installed alongside
        appDir + QStringLiteral("/../../target/debug/pontus-cli"),       // dev: gui/build → target
        appDir + QStringLiteral("/../../target/release/pontus-cli"),
    };
    for (const QString& candidate : candidates) {
        const QFileInfo info(candidate);
        if (info.isExecutable()) {
            return info.absoluteFilePath();
        }
    }
    return QStandardPaths::findExecutable(QStringLiteral("pontus-cli"));
}

void MainWindow::onFilterChanged(const QString& text) {
    proxy_->setFilterFixedString(text);
}

void MainWindow::reload() {
    model_->removeRows(0, model_->rowCount());
    history_->setRowCount(0);
    detailHeader_->setText(QStringLiteral("Select an asset"));
    macLabel_->clear();

    const QJsonArray assets = client_.assets();
    for (const QJsonValue& v : assets) {
        const QJsonObject a = v.toObject();
        QList<QStandardItem*> row;
        row << numericItem(a.value("id").toInt());
        row << textItem(a.value("identity_kind").toString());
        row << textItem(a.value("identity_value").toString());
        row << textItem(orDash(a.value("hostname")));
        row << textItem(orDash(a.value("last_ip")));
        row << textItem(orDash(a.value("mac")));
        row << textItem(orDash(a.value("os")));
        row << numericItem(a.value("observations").toInt());
        row << textItem(a.value("last_seen").toString());
        model_->appendRow(row);
    }
    table_->resizeColumnsToContents();
    table_->horizontalHeader()->setStretchLastSection(true);
    statusBar()->showMessage(
        QStringLiteral("%1 — %2 asset(s)").arg(client_.dbPath()).arg(assets.size()));
}

void MainWindow::onSelectionChanged() {
    const QModelIndexList rows = table_->selectionModel()->selectedRows();
    if (rows.isEmpty()) {
        return;
    }
    const QModelIndex src = proxy_->mapToSource(rows.first());
    const long long id = model_->item(src.row(), 0)->data(Qt::DisplayRole).toLongLong();
    const QString identity = model_->item(src.row(), 2)->text();
    const QString mac = model_->item(src.row(), 5)->text();
    showHistory(id, identity, mac);
}

void MainWindow::showHistory(long long assetId, const QString& identity, const QString& mac) {
    detailHeader_->setText(QStringLiteral("Asset %1 — %2").arg(assetId).arg(identity));
    const bool haveMac = !mac.isEmpty() && mac != QStringLiteral("-");
    macLabel_->setText(QStringLiteral("MAC: %1").arg(haveMac ? mac : QStringLiteral("— (no MAC learned)")));
    const QJsonArray history = client_.assetHistory(assetId);
    history_->setRowCount(history.size());
    for (int i = 0; i < history.size(); ++i) {
        const QJsonObject o = history.at(i).toObject();
        const QJsonObject state = o.value("state").toObject();
        history_->setItem(i, 0, new QTableWidgetItem(o.value("observed_at").toString()));
        history_->setItem(i, 1, new QTableWidgetItem(QString::number(o.value("scan_id").toInt())));
        history_->setItem(i, 2, new QTableWidgetItem(o.value("ip").toString()));
        history_->setItem(i, 3, new QTableWidgetItem(state.value("up").toBool() ? "yes" : "no"));
        const QJsonValue os = state.value("os_guess");
        history_->setItem(i, 4, new QTableWidgetItem(os.isString() ? os.toString() : QStringLiteral("-")));
        history_->setItem(i, 5, new QTableWidgetItem(portsSummary(state)));
    }
    history_->resizeColumnsToContents();
    history_->horizontalHeader()->setStretchLastSection(true);

    // Deep-inspection findings for the newest observation (history is newest-first).
    const QString inspection =
        history.isEmpty() ? QString() : inspectionText(history.at(0).toObject().value("state").toObject());
    inspection_->setPlainText(inspection.isEmpty()
                                  ? QStringLiteral("No TLS/web findings — scan with --inspect.")
                                  : inspection);
}
