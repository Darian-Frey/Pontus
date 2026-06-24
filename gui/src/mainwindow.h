#pragma once

#include <QMainWindow>

#include "pontusclient.h"

class QLabel;
class QLineEdit;
class QSortFilterProxyModel;
class QStandardItemModel;
class QTableView;
class QTableWidget;

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
    void onFilterChanged(const QString& text);
    void onSelectionChanged();

private:
    void reload();
    void showHistory(long long assetId, const QString& identity);

    PontusClient client_;
    QStandardItemModel* model_ = nullptr;
    QSortFilterProxyModel* proxy_ = nullptr;
    QTableView* table_ = nullptr;
    QLineEdit* filter_ = nullptr;
    QLabel* detailHeader_ = nullptr;
    QTableWidget* history_ = nullptr;
};
