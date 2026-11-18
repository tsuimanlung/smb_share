# -*- coding: utf-8 -*-
"""生成程序图标 staff.ico（供 build_exe.bat 调用）。

优先级：
  1. 已有 staff.ico            -> 直接跳过（本机发布包即这种情况）
  2. 有 staff_1024.jpg         -> 转成 16~256 多尺寸 ico
  3. 两者都没有（如刚 clone） -> 用 Pillow 画一个内置的「分享节点」图标
这样仓库里不需要附带任何二进制素材也能一键编译出带图标的 exe。
"""
import os
from PIL import Image, ImageDraw

SIZES = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ico = os.path.join(here, "staff.ico")
    jpg = os.path.join(here, "staff_1024.jpg")
    if os.path.exists(ico):
        print("staff.ico already exists, skipped")
        return
    if os.path.exists(jpg):
        im = Image.open(jpg).convert("RGB")
        w, h = im.size
        s = min(w, h)
        im = im.crop(((w - s) // 2, (h - s) // 2, (w - s) // 2 + s, (h - s) // 2 + s))
        print("generated staff.ico from staff_1024.jpg")
    else:
        im = Image.new("RGB", (256, 256), "#f0f2f0")
        d = ImageDraw.Draw(im)
        d.line([(72, 128), (184, 70)], fill="#2f7d46", width=12)
        d.line([(72, 128), (184, 186)], fill="#2f7d46", width=12)
        for x, y in ((64, 128), (192, 68), (192, 188)):
            d.ellipse([x - 28, y - 28, x + 28, y + 28],
                      fill="#3fa463", outline="#2f7d46", width=4)
        print("generated built-in share-node icon (no image assets found)")
    im.save(ico, format="ICO", sizes=SIZES)


if __name__ == "__main__":
    main()
