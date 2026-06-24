#pragma once

#include <QColor>
#include <QLabel>
#include <QPalette>

// Give a label a muted-but-readable foreground that adapts to the active theme:
// the theme's own text colour at reduced alpha. Using the fixed palette(mid) role
// renders too dark to read on dark themes.
inline void applyMutedText(QLabel* label) {
    QPalette palette = label->palette();
    QColor colour = palette.color(QPalette::WindowText);
    colour.setAlpha(160);
    palette.setColor(QPalette::WindowText, colour);
    label->setPalette(palette);
}
