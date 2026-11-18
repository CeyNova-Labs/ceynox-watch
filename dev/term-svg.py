#!/usr/bin/env python3
"""Render terminal output with ANSI colors as an SVG picture.

    ceynox-watch --color always -- npm install 2> run.ansi
    dev/term-svg.py '$ ceynox-watch -- npm install' < run.ansi > docs/demo.svg

Only the colors ceynox-watch uses are understood.
"""
import re
import sys
from xml.sax.saxutils import escape

FG = "#d7dae0"
STYLES = {
    "1": ("font-weight", "bold"),
    "2": ("fill", "#7d8590"),
    "31": ("fill", "#ff7b72"),
    "32": ("fill", "#7ee787"),
    "33": ("fill", "#e3b341"),
    "36": ("fill", "#79c0ff"),
}
CHAR_W, LINE_H, PAD, BAR = 8.6, 19, 18, 34


def spans(line):
    """Split a line into (text, {attribute: value}) runs."""
    out, style, pos = [], {}, 0
    for m in re.finditer(r"\x1b\[([0-9;]*)m", line):
        if m.start() > pos:
            out.append((line[pos:m.start()], dict(style)))
        for code in m.group(1).split(";") or ["0"]:
            if code in ("", "0"):
                style = {}
            elif code in STYLES:
                key, value = STYLES[code]
                style[key] = value
        pos = m.end()
    if pos < len(line):
        out.append((line[pos:], dict(style)))
    return out


def main():
    lines = [l.rstrip("\n") for l in sys.stdin]
    if len(sys.argv) > 1:
        lines.insert(0, f"\x1b[32m{sys.argv[1][:1]}\x1b[0m{sys.argv[1][1:]}")
    rows = [spans(l) for l in lines]
    cols = max((sum(len(t) for t, _ in r) for r in rows), default=0)
    width = round(cols * CHAR_W + 2 * PAD)
    height = BAR + len(rows) * LINE_H + PAD
    print(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
          f'role="img" aria-label="ceynox-watch watching npm install: an install script reads AWS credentials and an SSH key">')
    print(f'<rect width="{width}" height="{height}" rx="10" fill="#0d1117"/>')
    for i, color in enumerate(("#ff5f57", "#febc2e", "#28c840")):
        print(f'<circle cx="{PAD + 4 + i * 20}" cy="{BAR / 2 + 1}" r="6" fill="{color}"/>')
    print(f'<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="13" fill="{FG}" xml:space="preserve">')
    for n, row in enumerate(rows):
        y = BAR + (n + 1) * LINE_H - 5
        parts = []
        for text, style in row:
            attrs = "".join(f' {k}="{v}"' for k, v in style.items())
            # Non-breaking spaces: renderers collapse runs of ordinary ones,
            # which would lose the indentation.
            parts.append(f"<tspan{attrs}>{escape(text).replace(' ', chr(0xA0))}</tspan>")
        print(f'<text x="{PAD}" y="{y}">{"".join(parts)}</text>')
    print("</g></svg>")


if __name__ == "__main__":
    main()
