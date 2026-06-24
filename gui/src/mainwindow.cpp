#include "mainwindow.h"
#include "diffdialog.h"
#include "scandialog.h"

#include <QAction>
#include <QCoreApplication>
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
#include <QVBoxLayout>

namespace {
const QStringList kColumns = {"ID", "Anchor", "Identity", "Hostname", "Last IP", "Obs", "Last seen"};

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
    history_ = new QTableWidget;
    history_->setColumnCount(5);
    history_->setHorizontalHeaderLabels({"Observed at", "Scan", "IP", "Up", "Open ports"});
    history_->verticalHeader()->setVisible(false);
    history_->horizontalHeader()->setStretchLastSection(true);
    history_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    history_->setSelectionMode(QAbstractItemView::NoSelection);

    auto* rightBox = new QGroupBox(QStringLiteral("Asset detail"));
    auto* rightLayout = new QVBoxLayout(rightBox);
    rightLayout->addWidget(detailHeader_);
    rightLayout->addWidget(history_);

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

    const QJsonArray assets = client_.assets();
    for (const QJsonValue& v : assets) {
        const QJsonObject a = v.toObject();
        QList<QStandardItem*> row;
        row << numericItem(a.value("id").toInt());
        row << textItem(a.value("identity_kind").toString());
        row << textItem(a.value("identity_value").toString());
        row << textItem(orDash(a.value("hostname")));
        row << textItem(orDash(a.value("last_ip")));
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
    showHistory(id, identity);
}

void MainWindow::showHistory(long long assetId, const QString& identity) {
    detailHeader_->setText(QStringLiteral("Asset %1 — %2").arg(assetId).arg(identity));
    const QJsonArray history = client_.assetHistory(assetId);
    history_->setRowCount(history.size());
    for (int i = 0; i < history.size(); ++i) {
        const QJsonObject o = history.at(i).toObject();
        const QJsonObject state = o.value("state").toObject();
        history_->setItem(i, 0, new QTableWidgetItem(o.value("observed_at").toString()));
        history_->setItem(i, 1, new QTableWidgetItem(QString::number(o.value("scan_id").toInt())));
        history_->setItem(i, 2, new QTableWidgetItem(o.value("ip").toString()));
        history_->setItem(i, 3, new QTableWidgetItem(state.value("up").toBool() ? "yes" : "no"));
        history_->setItem(i, 4, new QTableWidgetItem(portsSummary(state)));
    }
    history_->resizeColumnsToContents();
    history_->horizontalHeader()->setStretchLastSection(true);
}
