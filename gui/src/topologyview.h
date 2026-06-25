#pragma once

#include <QGraphicsView>
#include <QHash>
#include <QList>
#include <QPointF>
#include <QString>

class QGraphicsScene;
class QGraphicsEllipseItem;
class QGraphicsSimpleTextItem;
class QGraphicsLineItem;
class QJsonArray;

// Force-directed topology graph (F-009): renders the traceroute edges as nodes
// (hosts/routers) and links, self-arranging with a spring layout on a timer. The
// scanner (a source that is never a destination) is pinned at the centre, so a
// flat /24 settles into a clean star.
class TopologyView : public QGraphicsView {
    Q_OBJECT
public:
    explicit TopologyView(QWidget* parent = nullptr);

    // Replace the graph with the edges from a `[{"from","to"}, …]` array.
    void setTopology(const QJsonArray& edges);

protected:
    void wheelEvent(QWheelEvent* event) override;

private:
    struct Node {
        QString ip;
        QPointF pos;
        bool scanner = false;
        QGraphicsEllipseItem* dot = nullptr;
        QGraphicsSimpleTextItem* label = nullptr;
    };
    struct Link {
        int a;
        int b;
        QGraphicsLineItem* line = nullptr;
    };

    void settle();      // run the force layout to rest (no rendering)
    void step();        // one force-layout iteration
    void rebuildScene();
    void syncItems();   // position items from node coordinates
    void frame();       // fit the graph in view, with pan margin

    QGraphicsScene* scene_;
    QList<Node> nodes_;
    QList<Link> links_;
    QHash<QString, int> index_;
    double temperature_ = 0.0;
};
