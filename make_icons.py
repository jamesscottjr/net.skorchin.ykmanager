#!/usr/bin/env python3
"""Generate launcher icons for the YubiKey Manager starter app."""
from PIL import Image, ImageDraw
import os

GREEN = (132, 188, 60, 255)      # Yubico-ish green
GREEN_DARK = (108, 158, 44, 255)
WHITE = (255, 255, 255, 255)

RES = "app/src/main/res"


def draw_key(draw, cx, cy, scale, color=WHITE):
    """Draw a simple horizontal key centered at cx, cy."""
    r = 9 * scale          # head radius
    shaft_len = 34 * scale
    shaft_h = 8 * scale
    # head
    draw.ellipse([cx - shaft_len / 2 - r, cy - r, cx - shaft_len / 2 + r, cy + r], fill=color)
    draw.ellipse([cx - shaft_len / 2 - r * 0.45, cy - r * 0.45,
                  cx - shaft_len / 2 + r * 0.45, cy + r * 0.45], fill=(0, 0, 0, 0))
    # shaft
    x0 = cx - shaft_len / 2 + r
    x1 = cx + shaft_len / 2
    draw.rectangle([x0, cy - shaft_h / 2, x1, cy + shaft_h / 2], fill=color)
    # teeth
    for i in range(2):
        tx = x1 - (i + 1) * 9 * scale
        draw.rectangle([tx - 3 * scale, cy + shaft_h / 2, tx + 3 * scale, cy + shaft_h / 2 + 8 * scale], fill=color)


def legacy(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    radius = size * 0.18
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=GREEN)
    d.rounded_rectangle([size * 0.04, size * 0.04, size * 0.96, size * 0.96],
                        radius=radius * 0.92, fill=GREEN_DARK)
    draw_key(d, size / 2, size / 2, size / 64.0)
    return img


def foreground(size):
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # safe zone is 66/108 of canvas; scale key to fit
    draw_key(d, size / 2, size / 2, size / 108.0 * 1.15)
    return img


def save(img, folder, name):
    path = os.path.join(RES, folder)
    os.makedirs(path, exist_ok=True)
    img.save(os.path.join(path, name))


if __name__ == "__main__":
    # Legacy full-bleed icons
    for dpi, size in [("mipmap-mdpi", 48), ("mipmap-hdpi", 72), ("mipmap-xhdpi", 96),
                      ("mipmap-xxhdpi", 144), ("mipmap-xxxhdpi", 192)]:
        save(legacy(size), dpi, "ic_launcher.png")
        save(legacy(size), dpi, "ic_launcher_round.png")

    # Adaptive icon foreground layers
    for dpi, size in [("mipmap-mdpi", 108), ("mipmap-hdpi", 162), ("mipmap-xhdpi", 216),
                      ("mipmap-xxhdpi", 324), ("mipmap-xxxhdpi", 432)]:
        save(foreground(size), dpi, "ic_launcher_foreground.png")

    print("icons generated")
