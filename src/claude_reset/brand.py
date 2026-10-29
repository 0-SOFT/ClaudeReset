"""0-soft brand for the window: colour tokens, process-private fonts, anti-aliased shapes as PNG.

No Tk here. Shapes are drawn from signed distances, one sample per pixel, and encoded
as RGBA PNG so Tk blends their edges with any background. Source: 0-soft brandbook
(github.com/0-SOFT/0-soft-brandbook, 06.10.2026): paper, marble, mist, graphite, one
accent (turquoise, fill and the person's choice only, never text).
"""
import functools
import math
import struct
import zlib
from pathlib import Path

LIGHT = {
    'paper': '#f2f1ec', 'marble': '#f8f7f4', 'mist': '#eceff1', 'haze': '#dce3e8',
    'stone': '#b9c0c8', 'graphite': '#2e3135', 'graphite2': '#4a4f56', 'ink': '#0e0e0e',
    'accent': '#92d0e3', 'on_accent': '#0e0e0e', 'good': '#2f6b4f', 'bad': '#b3261e',
}
# Dark theme of the brandbook: night sky instead of paper, marble instead of ink; the same turquoise,
# and text on turquoise stays ink in both themes.
DARK = {
    'paper': '#0f1214', 'marble': '#161a1d', 'mist': '#1b2024', 'haze': '#2b3238',
    'stone': '#4b545d', 'graphite': '#dde1e4', 'graphite2': '#a7afb7', 'ink': '#f5f4ef',
    'accent': '#92d0e3', 'on_accent': '#0e0e0e', 'good': '#8fd6b4', 'bad': '#ff9a8f',
}
PALETTES = {'light': LIGHT, 'dark': DARK}
# Families as named inside the bundled TTFs (static instances of the brand fonts).
FONTS = {'display': 'Cormorant Garamond Medium', 'body': 'Onest', 'medium': 'Onest Medium',
         'semibold': 'Onest SemiBold', 'mono': 'IBM Plex Mono Medium'}
FALLBACK = {'display': 'Georgia', 'body': 'Segoe UI', 'medium': 'Segoe UI Semibold',
            'semibold': 'Segoe UI Semibold', 'mono': 'Consolas'}
FONT_DIR = Path(__file__).with_name('assets') / 'fonts'
FR_PRIVATE = 0x10


def register_fonts(directory=FONT_DIR, *, add=None):
    """Load the bundled fonts for this process only; nothing is installed into Windows."""
    if add is None:
        import ctypes
        add = lambda path: ctypes.windll.gdi32.AddFontResourceExW(str(path), FR_PRIVATE, 0)
    loaded = []
    for file in sorted(Path(directory).glob('*.ttf')):
        try:
            if add(file) > 0:
                loaded.append(file.name)
        except Exception:
            pass
    return loaded


def enable_dpi_awareness(*, api=None):
    """Crisp text on scaled displays; affects this process only. Call before creating Tk."""
    try:
        if api is None:
            import ctypes
            api = ctypes.windll.shcore.SetProcessDpiAwareness
        api(1)
        return True
    except Exception:
        return False


@functools.lru_cache(maxsize=None)
def rgb(color):
    return tuple(int(color[i:i + 2], 16) for i in (1, 3, 5))


def png(width, height, pixel):
    """pixel(x, y) -> (r, g, b, a) at the pixel centre; returns PNG bytes."""
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            rows.extend(pixel(x + .5, y + .5))

    def chunk(tag, data):
        return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff)
    header = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    return b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', header) + chunk(b'IDAT', zlib.compress(bytes(rows), 9)) + chunk(b'IEND', b'')


def coverage(distance):
    return 1.0 if distance <= -.5 else 0.0 if distance >= .5 else .5 - distance


def compose(layers):
    """Layers bottom to top as (colour, alpha); returns an RGBA tuple."""
    r = g = b = a = 0.0
    for color, alpha in layers:
        if alpha <= 0:
            continue
        cr, cg, cb = rgb(color)
        out = alpha + a * (1 - alpha)
        r = (cr * alpha + r * a * (1 - alpha)) / out
        g = (cg * alpha + g * a * (1 - alpha)) / out
        b = (cb * alpha + b * a * (1 - alpha)) / out
        a = out
    return (round(r), round(g), round(b), round(a * 255))


def box_distance(x, y, width, height, radius):
    qx = abs(x - width / 2) - (width / 2 - radius)
    qy = abs(y - height / 2) - (height / 2 - radius)
    return math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - radius


def ellipse_distance(x, y, cx, cy, rx, ry):
    dx, dy = x - cx, y - cy
    f = (dx / rx) ** 2 + (dy / ry) ** 2 - 1
    grad = math.hypot(2 * dx / rx ** 2, 2 * dy / ry ** 2) or 1e-9
    return f / grad


def segment_distance(x, y, ax, ay, bx, by):
    vx, vy, wx, wy = bx - ax, by - ay, x - ax, y - ay
    t = max(0.0, min(1.0, (wx * vx + wy * vy) / (vx * vx + vy * vy)))
    return math.hypot(wx - t * vx, wy - t * vy)


def rounded(width, height, radius, fill=None, ring=None, ring_width=1.0, background=None):
    """Rounded rectangle (a pill when radius is half the height), optional inner ring.
    With a background the image is opaque and its edges are blended with that colour."""
    under = (background, 1 if background else 0)
    solid = compose([under, (fill, 1 if fill else 0)])
    outside = compose([under])

    def pixel(x, y):
        d = box_distance(x, y, width, height, radius)
        if d >= .5:
            return outside
        if d <= -.5 - (ring_width if ring else 0):
            return solid
        inside = coverage(d)
        band = max(0.0, inside - coverage(d + ring_width)) if ring else 0
        return compose([under, (fill, inside if fill else 0), (ring, band)])
    return png(width, height, pixel)


# The mark: two equal ellipses 40 x 45 in a 126 x 90 box, the lens (their intersection) cut out.
MARK_BOX = (12, 10, 126, 90)


def mark(height, left='#0e0e0e', right='#92d0e3', background=None):
    scale = height / MARK_BOX[3]
    width = round(MARK_BOX[2] * scale)

    def pixel(x, y):
        u, v = x / scale + MARK_BOX[0], y / scale + MARK_BOX[1]
        cl = coverage(ellipse_distance(u, v, 52, 55, 40, 45) * scale)
        cr = coverage(ellipse_distance(u, v, 98, 55, 40, 45) * scale)
        return compose([(background, 1 if background else 0), (left, cl * (1 - cr)), (right, cr * (1 - cl))])
    return png(width, height, pixel)


def lens(height, color='#92d0e3', background=None):
    """The lens marker for menus and tabs (34 x 73.64 in mark units)."""
    scale = height / 73.64
    width = max(2, round(34 * scale))

    def pixel(x, y):
        u, v = x / scale + 58, y / scale + 18.18
        cl = coverage(ellipse_distance(u, v, 52, 55, 40, 45) * scale)
        cr = coverage(ellipse_distance(u, v, 98, 55, 40, 45) * scale)
        return compose([(background, 1 if background else 0), (color, cl * cr)])
    return png(width, height, pixel)


def dot(size, color, background=None):
    return png(size, size, lambda x, y: compose([(background, 1 if background else 0),
                                                 (color, coverage(math.hypot(x - size / 2, y - size / 2) - size / 2 + .5))]))


def checkbox(size, checked, *, box='#f8f7f4', ring='#b9c0c8', on='#92d0e3', mark_color='#0e0e0e', background=None, gap=0):
    """A check box; gap adds empty space on the right, before the label."""
    radius = size * .28
    stroke = max(1.5, size * .1)

    def pixel(x, y):
        under = (background, 1 if background else 0)
        if x > size:
            return compose([under])
        d = box_distance(x, y, size, size, radius)
        inside = coverage(d)
        if not checked:
            return compose([under, (box, inside), (ring, max(0.0, inside - coverage(d + 1.5)))])
        tick = min(segment_distance(x, y, size * .27, size * .52, size * .43, size * .68),
                   segment_distance(x, y, size * .43, size * .68, size * .74, size * .34))
        return compose([under, (on, inside), (mark_color, coverage(tick - stroke / 2) * inside)])
    return png(size + gap, size, pixel)


def ico(sizes=(16, 20, 24, 32, 40, 48, 64, 128, 256)):
    """A Windows .ico of the application icon with PNG-compressed images (Vista and later)."""
    images = [app_icon(size) for size in sizes]
    header = struct.pack('<HHH', 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries = b''
    for size, data in zip(sizes, images):
        entries += struct.pack('<BBBBHHII', size % 256, size % 256, 0, 0, 1, 32, len(data), offset)
        offset += len(data)
    return header + entries + b''.join(images)


def app_icon(size):
    """Application icon: the night mark (paper and turquoise) on ink, as in the brandbook."""
    height = size * 71.43 / 180
    scale = height / MARK_BOX[3]
    left, top = (size - MARK_BOX[2] * scale) / 2, (size - height) / 2

    def pixel(x, y):
        u, v = (x - left) / scale + MARK_BOX[0], (y - top) / scale + MARK_BOX[1]
        cl = coverage(ellipse_distance(u, v, 52, 55, 40, 45) * scale)
        cr = coverage(ellipse_distance(u, v, 98, 55, 40, 45) * scale)
        return compose([('#0e0e0e', 1), ('#f2f1ec', cl * (1 - cr)), ('#92d0e3', cr * (1 - cl))])
    return png(size, size, pixel)
