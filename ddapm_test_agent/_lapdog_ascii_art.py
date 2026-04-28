from typing import List
from typing import Optional
from typing import Tuple

from . import _get_version

# Letter masks (5 rows tall). '#' = filled, ' ' = blank. All letters share the
# same height so they can be rendered side-by-side with a drop shadow.
_LAPDOG_LETTERS = (
    (
        "##    ",
        "##    ",
        "##    ",
        "##    ",
        "######",
    ),
    (
        " ##### ",
        "##   ##",
        "#######",
        "##   ##",
        "##   ##",
    ),
    (
        "###### ",
        "##   ##",
        "###### ",
        "##     ",
        "##     ",
    ),
    (
        "###### ",
        "##   ##",
        "##   ##",
        "##   ##",
        "###### ",
    ),
    (
        " ##### ",
        "##   ##",
        "##   ##",
        "##   ##",
        " ##### ",
    ),
    (
        " ##### ",
        "##     ",
        "##  ###",
        "##   ##",
        " ##### ",
    ),
)


def _render_lapdog_art(face: str, shadow: str, reset: str) -> List[str]:
    """Render LAPDOG word art as colored lines with a 1-cell drop shadow.

    Produces a mask of filled cells by concatenating the letter masks with one
    blank column between each letter, then draws a shadow copy offset +1 col /
    +1 row behind the face so the letters appear to have depth.
    """
    gap = 1
    height = len(_LAPDOG_LETTERS[0])
    # Build a single filled/blank grid across all letters.
    rows: List[str] = [""] * height
    for i, letter in enumerate(_LAPDOG_LETTERS):
        for y in range(height):
            rows[y] += letter[y]
        if i != len(_LAPDOG_LETTERS) - 1:
            for y in range(height):
                rows[y] += " " * gap

    w = len(rows[0])
    # Shadow canvas is one row taller and one column wider (shadow offset).
    out_h = height + 1
    out_w = w + 1

    def filled(y: int, x: int) -> bool:
        if 0 <= y < height and 0 <= x < w:
            return rows[y][x] == "#"
        return False

    # Flood-fill from outside the canvas to identify "outside" blank cells.
    # Shadows should only be drawn on outside cells, never inside letter holes
    # (the interiors of O, D, P, A, G).
    outside = [[False] * out_w for _ in range(out_h)]
    # Seed the flood fill from every non-filled cell on the border so letters
    # that touch the top-left corner (like 'L') don't block the fill.
    stack: List[Tuple[int, int]] = []
    for x in range(out_w):
        stack.append((0, x))
        stack.append((out_h - 1, x))
    for y in range(out_h):
        stack.append((y, 0))
        stack.append((y, out_w - 1))
    while stack:
        y, x = stack.pop()
        if not (0 <= y < out_h and 0 <= x < out_w):
            continue
        if outside[y][x] or filled(y, x):
            continue
        outside[y][x] = True
        stack.extend([(y + 1, x), (y - 1, x), (y, x + 1), (y, x - 1)])

    lines: List[str] = []
    for y in range(out_h):
        segments: List[str] = []
        current: Optional[str] = None  # None | "face" | "shadow"
        buf: List[str] = []

        def flush() -> None:
            if not buf:
                return
            color = face if current == "face" else shadow if current == "shadow" else ""
            segments.append(f"{color}{''.join(buf)}{reset}" if color else "".join(buf))

        for x in range(out_w):
            is_face = filled(y, x)
            is_shadow = (not is_face) and outside[y][x] and filled(y - 1, x - 1)
            kind = "face" if is_face else "shadow" if is_shadow else None
            ch = "█" if (is_face or is_shadow) else " "
            if kind != current:
                flush()
                buf = []
                current = kind
            buf.append(ch)
        flush()
        lines.append("".join(segments))
    return lines


def _build_running_banner() -> str:
    face = "\033[38;5;177m"  # light purple
    shadow = "\033[38;5;54m"  # deep purple
    dim = "\033[2m"
    bold = "\033[1m"
    reset = "\033[0m"

    art_lines = _render_lapdog_art(face, shadow, reset)

    right_lines = [
        f"{bold}lapdog{reset} {dim}v{_get_version()}{reset}",
        "",
        f"{dim}Lapdog has started and is listening for data.{reset}",
        f"{dim}Open {reset}{face}https://lapdog.datadoghq.com{reset}{dim} to view data{reset}",
        f"{dim}related to this coding session.{reset}",
    ]
    # Vertically center the text block against the art.
    pad_top = max((len(art_lines) - len(right_lines)) // 2, 0)
    padded_right = [""] * pad_top + right_lines
    while len(padded_right) < len(art_lines):
        padded_right.append("")

    lines = [""]
    for art, text in zip(art_lines, padded_right):
        lines.append(f"  {art}  {text}")
    lines.append("")
    return "\n".join(lines)


LAPDOG_RUNNING = _build_running_banner()
