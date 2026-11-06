"""Генерация иконки SWCC: .ico с наборами размеров + RGBA 64x64 для окна."""
import base64
import os
import struct
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(os.path.dirname(HERE), "assets")
os.makedirs(ASSETS, exist_ok=True)

SS = 4  # суперсэмплинг
N = 256  # базовый размер


def lerp(a, b, t):
    return a + (b - a) * t


def smooth(edge, x, width=1.0):
    """Мягкая граница в координатах пикселей с учётом суперсэмплинга."""
    t = (x - edge) / width
    if t <= 0:
        return 0.0
    if t >= 1:
        return 1.0
    return t * t * (3 - 2 * t)


def capsule_dist(px, py, ax, ay, bx, by):
    vx, vy = bx - ax, by - ay
    wx, wy = px - ax, py - ay
    seg = vx * vx + vy * vy
    t = max(0.0, min(1.0, (wx * vx + wy * vy) / seg))
    cx, cy = ax + vx * t, ay + vy * t
    return ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5


def circle_dist(px, py, cx, cy, r):
    return ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5 - r


def rounded_rect_alpha(px, py, x0, y0, x1, y1, radius):
    """Сглаженный rounded rect: 1 внутри, 0 снаружи."""
    cx = min(max(px, x0 + radius), x1 - radius)
    cy = min(max(py, y0 + radius), y1 - radius)
    d = ((px - max(min(px, x1 - radius), x0 + radius)) ** 2
         + (py - max(min(py, y1 - radius), y0 + radius)) ** 2) ** 0.5
    edge = radius if (px < x0 + radius or px > x1 - radius or py < y0 + radius or py > y1 - radius) else 0
    inside = (x0 <= px <= x1) and (y0 <= py <= y1)
    if edge == 0:
        return 1.0 if inside else 0.0
    return 1.0 if d <= edge else 0.0


def compose(px, py):
    """Цвет пикселя в координатах 256x256 (float) -> (r,g,b,a) 0..255."""
    w = 256.0
    # фон: скруглённый квадрат с вертикальным градиентом
    a_bg = 0.0
    x0, y0, x1, y1, rad = 4.0, 4.0, w - 4.0, w - 4.0, w * 0.225
    if x0 - 1 <= px <= x1 + 1 and y0 - 1 <= py <= y1 + 1:
        cx = min(max(px, x0 + rad), x1 - rad)
        cy = min(max(py, y0 + rad), y1 - rad)
        d = ((px - cx) ** 2 + (py - cy) ** 2) ** 0.5
        a_bg = max(0.0, min(1.0, rad + 0.9 - d))
    if a_bg <= 0:
        return (0, 0, 0, 0)
    t = py / w
    col = (
        int(lerp(22, 12, t)),
        int(lerp(28, 20, t)),
        int(lerp(58, 46, t)),
    )
    # мягкое световое пятно сверху-слева
    glow = max(0.0, 1.0 - circle_dist(px, py, w * 0.34, w * 0.28, w * 0.55) / 70.0 - 0.55)
    col = (
        min(255, int(col[0] + glow * 26)),
        min(255, int(col[1] + glow * 22)),
        min(255, int(col[2] + glow * 40)),
    )

    horizon = w * 0.60
    sun_cx, sun_cy, sun_r = w * 0.455, horizon, w * 0.150

    def over(base, ocol, oa):
        if oa <= 0:
            return base
        if oa >= 1:
            return ocol
        return tuple(int(lerp(b, o, oa)) for b, o in zip(base, ocol))

    # солнце (нижняя половина отрезается горизонтом)
    ds = circle_dist(px, py, sun_cx, sun_cy, sun_r)
    if ds < 1.0 and py < horizon:
        st = (horizon - py) / sun_r
        sun = (int(lerp(255, 255, st)), int(lerp(150, 205, st)), int(lerp(70, 120, st)))
        col = over(col, sun, max(0.0, min(1.0, 1.0 - ds)))

    # линия горизонта
    if abs(py - horizon) < w * 0.017:
        hl = max(0.0, 1.0 - abs(py - horizon) / (w * 0.017))
        if abs(px - w * 0.455) < w * 0.30:
            col = over(col, (96, 220, 210), hl)

    # лучи солнца
    for k, ang in enumerate((-90, -55, -125)):
        import math

        ax = sun_cx + math.cos(math.radians(ang)) * (sun_r + w * 0.045)
        ay = sun_cy + math.sin(math.radians(ang)) * (sun_r + w * 0.045)
        bx = sun_cx + math.cos(math.radians(ang)) * (sun_r + w * 0.105)
        by = sun_cy + math.sin(math.radians(ang)) * (sun_r + w * 0.105)
        d = capsule_dist(px, py, ax, ay, bx, by)
        if d < w * 0.020:
            col = over(col, (255, 190, 110), max(0.0, min(1.0, (w * 0.020 - d) / 2.0)))

    # лупа: кольцо + ручка
    lens_r, ring = w * 0.295, w * 0.032
    dl = abs(circle_dist(px, py, w * 0.44, w * 0.46, lens_r))
    if dl < ring:
        col = over(col, (232, 240, 255), max(0.0, min(1.0, (ring - dl) / 2.2)))
    hx, hy = w * 0.44 + lens_r * 0.71, w * 0.46 + lens_r * 0.71
    dh = capsule_dist(px, py, hx, hy, w * 0.855, w * 0.865)
    if dh < w * 0.045:
        col = over(col, (232, 240, 255), max(0.0, min(1.0, (w * 0.045 - dh) / 2.2)))

    return (col[0], col[1], col[2], int(round(a_bg * 255)))


def render(size):
    """Рендерим size x size из базовой сетки 256 с суперсэмплингом."""
    scale = size / N
    px_rows = []
    step = 1.0 / (size * SS)
    for sy in range(size):
        row = []
        for sx in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]
            wsum = [0.0, 0.0, 0.0]
            for oy in range(SS):
                for ox in range(SS):
                    gx = (sx + (ox + 0.5) / SS) / scale
                    gy = (sy + (oy + 0.5) / SS) / scale
                    r, g, b, a = compose(gx, gy)
                    acc[3] += a / 255.0
                    wsum[0] += r * a / 255.0
                    wsum[1] += g * a / 255.0
                    wsum[2] += b * a / 255.0
            samples = SS * SS
            alpha = acc[3] / samples
            if alpha > 0:
                row.append(
                    (
                        int(min(255, wsum[0] / acc[3])),
                        int(min(255, wsum[1] / acc[3])),
                        int(min(255, wsum[2] / acc[3])),
                        int(round(alpha * 255)),
                    )
                )
            else:
                row.append((0, 0, 0, 0))
        px_rows.append(row)
    return px_rows


def rgba_bytes(img):
    out = bytearray()
    for row in img:
        for r, g, b, a in row:
            out += bytes((r, g, b, a))
    return bytes(out)


def png(img, size):
    raw = bytearray()
    for row in img:
        raw.append(0)
        for r, g, b, a in row:
            raw += bytes((r, g, b, a))

    def chunk(tag, data):
        return (
            struct.pack(">I", len(data))
            + tag
            + data
            + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw), 9))
        + chunk(b"IEND", b"")
    )


SIZES = [256, 128, 64, 48, 32, 24, 16]
imgs = {s: render(s) for s in SIZES}

# --- .ico ---------------------------------------------------------------
entries = []
for s in SIZES:
    data = png(imgs[s], s)
    entries.append((s, data))
hdr = struct.pack("<HHH", 0, 1, len(entries))
body = b""
dir_ = b""
offset = 6 + 16 * len(entries)
for s, data in entries:
    dim = 0 if s >= 256 else s
    dir_ += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset)
    body += data
    offset += len(data)
ico_path = os.path.join(ASSETS, "icon.ico")
with open(ico_path, "wb") as f:
    f.write(hdr + dir_ + body)

# --- отдельные PNG для превью ------------------------------------------
for s in (256, 32):
    with open(os.path.join(ASSETS, f"icon-{s}.png"), "wb") as f:
        f.write(png(imgs[s], s))

# --- RGBA 64x64 для иконки окна (base64) -------------------------------
b64 = base64.b64encode(rgba_bytes(imgs[64])).decode()
rust = (
    "// Иконка окна: 64x64 RGBA, сгенерировано tools/make_icon.py.\n"
    "// Файл не правят руками - пересобирают скриптом.\n"
    "use base64::{engine::general_purpose::STANDARD, Engine};\n\n"
    f'const RGBA_B64: &str = "{b64}";\n\n'
    + "pub const ICON_SIZE: u32 = 64;\n\n"
    "pub fn rgba() -> Vec<u8> {\n"
    "    STANDARD.decode(RGBA_B64).expect(\"иконка повреждена в исходниках\")\n"
    "}\n"
)
with open(os.path.join(os.path.dirname(HERE), "src", "icon_data.rs"), "w", encoding="utf-8") as f:
    f.write(rust)
print("ok:", ico_path, len(rgba_bytes(imgs[64])))
