#pragma once

#include <QMainWindow>

#include "pontusclient.h"

class QLabel;
class QLineEdit;
class QSortFilterProxyModel;
class QStandardItemModel;
class QTableView;
class QTableWidget;
class QTextEdit;

// The Pontus home screen (F-008): the asset inventory as a filterable table with a
// detail pane showing the selected asset's observation history. Reads through the
// pontus-ffi shim; displays a store the CLI populated.
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

    // Open and display a store; safe to call with an empty path (no-op).
    void openDatabase(const QString& path);

private slots:
    void onOpen();
    void onRefresh();
    void onNewScan();
    void onDiff();
    void onHeatmap();
    void onTopology();
    void onRisk();
    void onNetConfig();
    void onFilterChanged(const QString& text);
    void onSelectionChanged();

private:
    void reload();
    void showHistory(long long assetId, const QString& identity);
    // Locate a pontus-cli to drive scans (D-008): $PONTUS_CLI, then alongside the
    // GUI / the dev target dir, then PATH. Empty if none found.
    QString findPontusCli() const;

    PontusClient client_;
    QStandardItemModel* model_ = nullptr;
    QSortFilterProxyModel* proxy_ = nullptr;
    QTableView* table_ = nullptr;
    QLineEdit* filter_ = nullptr;
    QLabel* detailHeader_ = nullptr;
    QTableWidget* history_ = nullptr;
    QTextEdit* inspection_ = nullptr;
};
