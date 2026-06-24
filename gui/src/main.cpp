#include <QApplication>
#include <QJsonArray>
#include <QJsonObject>
#include <QString>

#include <iostream>

#include "mainwindow.h"
#include "pontusclient.h"

// Headless self-test: open a store through the shim, print a summary, exit. Lets
// the GUI's FFI/JSON path be verified without a display (CI / sandbox):
//   pontus-gui --selftest path/to/pontus.db
static int selftest(const QString& dbPath) {
    PontusClient client;
    if (!client.open(dbPath)) {
        std::cerr << "selftest: failed to open " << dbPath.toStdString() << "\n";
        return 1;
    }
    const QJsonArray assets = client.assets();
    std::cout << "pontus-gui selftest ok: version=" << client.version().toStdString()
              << " assets=" << assets.size() << "\n";
    if (!assets.isEmpty()) {
        const QJsonObject first = assets.at(0).toObject();
        const long long id = first.value("id").toInt();
        std::cout << "  first asset: id=" << id
                  << " identity=" << first.value("identity_value").toString().toStdString()
                  << " history=" << client.assetHistory(id).size() << " observation(s)\n";
    }

    // Exercise the diff path (the data side of the drift view) over the two newest scans.
    const QJsonArray scans = client.scans(10);
    if (scans.size() >= 2) {
        const long long toId = scans.at(0).toObject().value("id").toInt();
        const long long fromId = scans.at(1).toObject().value("id").toInt();
        int changed = 0;
        for (const QJsonValue& v : client.diff(fromId, toId)) {
            if (v.toObject().value("status").toString() != QStringLiteral("Unchanged")) {
                ++changed;
            }
        }
        std::cout << "  diff scan " << fromId << "->" << toId << ": " << changed
                  << " host(s) changed/new/vanished\n";
    }
    return 0;
}

int main(int argc, char** argv) {
    // Pre-scan for the headless self-test so we never need a display for it.
    if (argc >= 3 && QString::fromLocal8Bit(argv[1]) == QStringLiteral("--selftest")) {
        return selftest(QString::fromLocal8Bit(argv[2]));
    }

    QApplication app(argc, argv);
    MainWindow window;
    // Optional positional argument: a database to open on launch.
    const QStringList args = QApplication::arguments();
    if (args.size() >= 2) {
        window.openDatabase(args.at(1));
    }
    window.show();
    return app.exec();
}
