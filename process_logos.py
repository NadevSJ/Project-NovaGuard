"""One-off script to remove backgrounds from NovaGuard logo files.

Run: python process_logos.py
"""
from PIL import Image
import numpy as np


def remove_white_bg(src: str, dst: str, threshold: int = 230) -> None:
    img = Image.open(src).convert("RGBA")
    data = np.array(img)
    r, g, b = data[:, :, 0], data[:, :, 1], data[:, :, 2]
    mask = (r > threshold) & (g > threshold) & (b > threshold)
    data[mask, 3] = 0
    Image.fromarray(data).save(dst)
    print(f"  {src} -> {dst}  (white bg removed)")


def remove_dark_bg(src: str, dst: str, threshold: int = 40) -> None:
    img = Image.open(src).convert("RGBA")
    data = np.array(img)
    r, g, b = data[:, :, 0], data[:, :, 1], data[:, :, 2]
    mask = (r < threshold) & (g < threshold) & (b < threshold)
    data[mask, 3] = 0
    Image.fromarray(data).save(dst)
    print(f"  {src} -> {dst}  (dark bg removed)")


if __name__ == "__main__":
    print("Processing NovaGuard logos...")
    remove_white_bg("logo/logo1.jpeg", "logo/logo1_nobg.png")
    remove_dark_bg("logo/logo2.jpeg",  "logo/logo2_nobg.png")
    remove_white_bg("logo/logo3.jpeg", "logo/logo3_nobg.png")
    print("Done.")
