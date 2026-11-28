#!/usr/bin/python3
"""Draws the boot splash: a mountain ridge under a faint aurora, and the name.

    image/branding/splash.py OUT.bmp

The Torngat Mountains and their northern lights: landscape only, no cultural symbols. A 24-bit BMP
that the UKI's stub shows centred while the kernel loads. Its edges fade to black, so it blends into
the screen around it. The same file every time (fixed seed). Needs Pillow and DejaVu Sans (Debian
fonts-dejavu-core).
"""

import math
import random
import sys

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

W, H = 640, 240
S = 3  # drawn this many times larger, then scaled down: smooth edges
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"


def ridge(rng, base, peaks, rough):
    """A ridge line across the width, `base` pixels down: straight lines between `peaks` (x, height)
    points, then roughened by midpoint displacement (`rough` pixels at the first step, halved each
    step)."""
    pts = [(0.0, base - peaks[0][1])] + [(x * W, base - h) for x, h in peaks] + [(W, base - peaks[-1][1])]
    step = rough
    for _ in range(6):
        out = []
        for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
            out.append((x0, y0))
            out.append(((x0 + x1) / 2, (y0 + y1) / 2 + rng.uniform(-step, step)))
        out.append(pts[-1])
        pts = out
        step /= 2
    return [(x * S, y * S) for x, y in pts]


def aurora():
    """Soft curtains, green to teal, brightest in the middle of the sky."""
    img = Image.new("RGB", (W * S, H * S))
    d = ImageDraw.Draw(img)
    for top, amp, phase, colour in [
        (40, 14, 0.4, (40, 150, 110)),
        (58, 10, 1.9, (28, 112, 128)),
        (30, 7, 3.2, (60, 170, 120)),
    ]:
        for x in range(0, W * S, S):
            u = x / (W * S)
            y0 = (top + amp * math.sin(u * 5.0 + phase) + 4 * math.sin(u * 13 + phase)) * S
            fade = math.sin(math.pi * u) ** 1.6
            for k in range(0, 30 * S, S):
                a = fade * (1 - k / (30 * S)) ** 2 * 0.75
                d.rectangle(
                    [x, y0 + k, x + S, y0 + k + S],
                    fill=tuple(int(v * a) for v in colour),
                )
    return img.filter(ImageFilter.GaussianBlur(5 * S))


def main(out):
    rng = random.Random(1979)
    img = Image.new("RGB", (W * S, H * S))
    d = ImageDraw.Draw(img)

    # Night sky, darkest at the top.
    for y in range(H * S):
        t = y / (H * S)
        d.line([(0, y), (W * S, y)], fill=(int(4 + 10 * t), int(7 + 14 * t), int(16 + 24 * t)))
    img = ImageChops.add(img, aurora())
    d = ImageDraw.Draw(img)

    # Stars, sparse, above the mountains.
    for _ in range(60):
        x, y = rng.uniform(0, W * S), rng.uniform(0, 110 * S)
        v = int(rng.uniform(70, 170))
        d.ellipse([x, y, x + S, y + S], fill=(v, v, min(255, v + 10)))

    # A far ridge, lighter, and a near one, dark, with the light on its edge.
    far = ridge(
        rng,
        172,
        [(0.06, 40), (0.14, 78), (0.2, 52), (0.3, 96), (0.38, 58), (0.52, 104), (0.6, 66), (0.7, 88),
         (0.79, 50), (0.88, 82), (0.96, 46)],
        12,
    )
    near = ridge(
        rng,
        184,
        [(0.04, 22), (0.12, 58), (0.19, 30), (0.27, 46), (0.4, 24), (0.46, 66), (0.55, 34), (0.66, 60),
         (0.74, 28), (0.84, 52), (0.93, 26)],
        10,
    )
    d.polygon(far + [(W * S, H * S), (0, H * S)], fill=(24, 32, 52))
    d.polygon(near + [(W * S, H * S), (0, H * S)], fill=(8, 11, 20))
    d.line(near, fill=(64, 80, 104), width=S)

    # The name.
    font = ImageFont.truetype(FONT, 24 * S)
    text = "T O R N G A T"
    box = d.textbbox((0, 0), text, font=font)
    d.text(((W * S - (box[2] - box[0])) / 2, 196 * S), text, font=font, fill=(214, 224, 236))

    img = img.resize((W, H), Image.LANCZOS)

    # Every edge fades to black.
    px = img.load()
    for y in range(H):
        for x in range(W):
            e = min(x, W - 1 - x, y, H - 1 - y) / 24
            if e < 1:
                px[x, y] = tuple(int(c * e) for c in px[x, y])
    img.save(out, "BMP")


if __name__ == "__main__":
    main(sys.argv[1])
