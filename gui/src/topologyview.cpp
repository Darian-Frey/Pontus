#include "topologyview.h"

#include <QGraphicsEllipseItem>
#include <QGraphicsLineItem>
#include <QGraphicsScene>
#include <QGraphicsSimpleTextItem>
#include <QJsonArray>
#include <QJsonObject>
#include <QSet>
#include <QWheelEvent>

#include <cmath>

namespace {
constexpr double kIdealLength = 110.0; // preferred edge length, scene units
constexpr double kInitTemp = 60.0;     // initial max move per iteration
constexpr double kCooling = 0.95;
constexpr double kStopTemp = 0.3;
constexpr int kMaxIterations = 600;
constexpr double kNodeRadius = 7.0;
constexpr double kScannerRadius = 10.0;

double length(const QPointF& p) {
    return std::hypot(p.x(), p.y());
}
} // namespace

TopologyView::TopologyView(QWidget* parent) : QGraphicsView(parent) {
    scene_ = new QGraphicsScene(this);
    setScene(scene_);
    setRenderHint(QPainter::Antialiasing, true);
    setDragMode(QGraphicsView::ScrollHandDrag);          // left-drag pans
    setTransformationAnchor(QGraphicsView::AnchorUnderMouse); // zoom under cursor
}

void TopologyView::wheelEvent(QWheelEvent* event) {
    const double factor = event->angleDelta().y() > 0 ? 1.15 : 1.0 / 1.15;
    scale(factor, factor);
}

void TopologyView::setTopology(const QJsonArray& edges) {
    nodes_.clear();
    links_.clear();
    index_.clear();
    scene_->clear();
    scene_->setSceneRect(QRectF());
    resetTransform();

    if (edges.isEmpty()) {
        auto* note = scene_->addSimpleText(
            QStringLiteral("No topology data for this scan.\n"
                           "Run a privileged scan (traceroute needs CAP_NET_RAW)."));
        note->setBrush(palette().placeholderText());
        return;
    }

    // Build nodes; remember which IPs are ever a destination so the pure source
    // (the scanner) can be pinned at the centre.
    QSet<QString> destinations;
    auto ensure = [&](const QString& ip) -> int {
        auto it = index_.constFind(ip);
        if (it != index_.constEnd()) {
            return it.value();
        }
        const int idx = nodes_.size();
        index_.insert(ip, idx);
        nodes_.append(Node{ip, QPointF(), false, nullptr, nullptr});
        return idx;
    };
    for (const QJsonValue& v : edges) {
        const QJsonObject e = v.toObject();
        const QString from = e.value(QStringLiteral("from")).toString();
        const QString to = e.value(QStringLiteral("to")).toString();
        if (from.isEmpty() || to.isEmpty()) {
            continue;
        }
        destinations.insert(to);
        links_.append(Link{ensure(from), ensure(to), nullptr});
    }

    const int n = nodes_.size();
    for (int i = 0; i < n; ++i) {
        nodes_[i].scanner = !destinations.contains(nodes_[i].ip);
        // Initial layout: scanner(s) centred, the rest spread on a ring.
        if (nodes_[i].scanner) {
            nodes_[i].pos = QPointF(0, 0);
        } else {
            const double angle = (2.0 * M_PI * i) / std::max(1, n);
            nodes_[i].pos = QPointF(std::cos(angle), std::sin(angle)) * 180.0;
        }
    }

    settle();        // converge before we draw — no on-screen jitter
    rebuildScene();
    frame();
}

void TopologyView::settle() {
    temperature_ = kInitTemp;
    for (int i = 0; i < kMaxIterations && temperature_ > kStopTemp; ++i) {
        step();
    }
}

void TopologyView::step() {
    const int n = nodes_.size();
    if (n == 0) {
        return;
    }

    QList<QPointF> disp;
    disp.fill(QPointF(0, 0), n);

    // Repulsion between every pair of nodes.
    for (int i = 0; i < n; ++i) {
        for (int j = i + 1; j < n; ++j) {
            QPointF delta = nodes_[i].pos - nodes_[j].pos;
            double dist = length(delta);
            if (dist < 0.01) {
                delta = QPointF(0.1 * (i - j) + 0.1, 0.1);
                dist = length(delta);
            }
            const QPointF dir = delta / dist;
            const double force = (kIdealLength * kIdealLength) / dist;
            disp[i] += dir * force;
            disp[j] -= dir * force;
        }
    }

    // Attraction along edges.
    for (const Link& link : links_) {
        QPointF delta = nodes_[link.a].pos - nodes_[link.b].pos;
        double dist = length(delta);
        if (dist < 0.01) {
            dist = 0.01;
        }
        const QPointF dir = delta / dist;
        const double force = (dist * dist) / kIdealLength;
        disp[link.a] -= dir * force;
        disp[link.b] += dir * force;
    }

    // Apply, capped by the cooling temperature; the scanner stays pinned.
    for (int i = 0; i < n; ++i) {
        if (nodes_[i].scanner) {
            continue;
        }
        const double d = length(disp[i]);
        if (d > 0.01) {
            nodes_[i].pos += (disp[i] / d) * std::min(d, temperature_);
        }
    }
    temperature_ *= kCooling;
}

void TopologyView::rebuildScene() {
    scene_->clear();

    QPen linkPen(QColor(0x88, 0x88, 0x88, 0xb0));
    linkPen.setWidthF(1.0);
    for (Link& link : links_) {
        link.line = scene_->addLine(QLineF(), linkPen); // links under nodes
    }

    const QBrush scannerBrush(QColor(0x27, 0xae, 0x60)); // green
    const QBrush nodeBrush(QColor(0x34, 0x98, 0xdb));     // blue
    const QPen outline(QColor(0x22, 0x22, 0x22));
    for (Node& node : nodes_) {
        const double r = node.scanner ? kScannerRadius : kNodeRadius;
        node.dot = scene_->addEllipse(-r, -r, 2 * r, 2 * r, outline,
                                      node.scanner ? scannerBrush : nodeBrush);
        node.label = scene_->addSimpleText(node.ip);
        node.label->setBrush(palette().text());
    }
    syncItems();
}

void TopologyView::syncItems() {
    for (const Link& link : links_) {
        link.line->setLine(QLineF(nodes_[link.a].pos, nodes_[link.b].pos));
    }
    for (const Node& node : nodes_) {
        node.dot->setPos(node.pos);
        const double r = node.scanner ? kScannerRadius : kNodeRadius;
        node.label->setPos(node.pos + QPointF(r + 3, -r - 2));
    }
}

void TopologyView::frame() {
    const QRectF bounds = scene_->itemsBoundingRect();
    // A scene rect larger than the content leaves room to drag-pan.
    scene_->setSceneRect(bounds.adjusted(-bounds.width() - 80, -bounds.height() - 80,
                                         bounds.width() + 80, bounds.height() + 80));
    fitInView(bounds.adjusted(-30, -30, 30, 30), Qt::KeepAspectRatio);
}
