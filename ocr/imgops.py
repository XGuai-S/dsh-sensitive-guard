"""Cross-platform image operations for dsh-sensitive-guard.

One CLI, one dependency (Pillow), used when the Windows PowerShell backend is
not available. Every subcommand writes a binary result file rather than stdout,
because a confined host cannot capture piped stdio.

Subcommands
-----------
pixels    Decode an image to raw BGRA.
          Output: int32 width, int32 height, then width*height*4 bytes.
redact    Fill rectangles with an opaque color and re-encode as PNG.
compress  Downscale so the long edge fits, re-encode as JPEG.
          Output: int32 width, int32 height, then the JPEG bytes.
ocr       Recognize text with the tesseract CLI, emitting boxes.
          Output: one line per box, "x\ty\tw\th\ttext".

Irreversibility of `redact` comes from three things: an opaque fill, a full
re-encode from the modified raster, and a save that writes no metadata.
"""

import argparse
import subprocess
import sys

try:
    from PIL import Image, ImageDraw
except ImportError:  # pragma: no cover - reported to the caller
    sys.stderr.write("MISSING_PIL\n")
    sys.exit(3)


def cmd_pixels(args):
    with Image.open(args.path) as img:
        rgba = img.convert("RGBA")
        width, height = rgba.size
        data = bytearray(rgba.tobytes())
    # RGBA -> BGRA
    data[0::4], data[2::4] = data[2::4], data[0::4]
    with open(args.out, "wb") as handle:
        handle.write(width.to_bytes(4, "little", signed=True))
        handle.write(height.to_bytes(4, "little", signed=True))
        handle.write(bytes(data))


def cmd_redact(args):
    with Image.open(args.path) as img:
        canvas = img.convert("RGBA")
    draw = ImageDraw.Draw(canvas)
    color = args.color
    if color.startswith("#"):
        color = color[1:]
    rgb = tuple(int(color[i:i + 2], 16) for i in (0, 2, 4)) + (255,)

    width, height = canvas.size
    for entry in args.boxes.split(";"):
        if not entry:
            continue
        parts = entry.split(",")
        if len(parts) != 4:
            continue
        x, y, w, h = (int(p) for p in parts)
        if w <= 0 or h <= 0:
            continue
        x0 = max(0, x)
        y0 = max(0, y)
        x1 = min(width, x + w)
        y1 = min(height, y + h)
        draw.rectangle([x0, y0, x1 - 1, y1 - 1], fill=rgb)

    # A fresh encode with no metadata keeps EXIF/GPS/camera fields out.
    canvas.convert("RGB").save(args.out, format="PNG", optimize=False)


def cmd_compress(args):
    with Image.open(args.path) as img:
        canvas = img.convert("RGB")
    width, height = canvas.size
    long_edge = max(width, height)
    if long_edge > args.max_dimension:
        scale = args.max_dimension / long_edge
        width = max(1, round(width * scale))
        height = max(1, round(height * scale))
        canvas = canvas.resize((width, height), Image.LANCZOS)
    canvas.save(args.out, format="JPEG", quality=85, optimize=True)
    with open(args.out, "rb") as handle:
        jpeg = handle.read()
    with open(args.out, "wb") as handle:
        handle.write(width.to_bytes(4, "little", signed=True))
        handle.write(height.to_bytes(4, "little", signed=True))
        handle.write(jpeg)


def cmd_ocr(args):
    command = [
        args.tesseract,
        args.path,
        "stdout",
        "-l", args.language,
        "--psm", "3",
        "tsv",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            timeout=args.timeout,
            check=False,
        )
    except FileNotFoundError:
        sys.stderr.write("MISSING_TESSERACT\n")
        return 4
    except subprocess.TimeoutExpired:
        sys.stderr.write("OCR_TIMEOUT\n")
        return 5

    if completed.returncode != 0:
        sys.stderr.write("OCR_FAILED\n")
        return 6

    rows = completed.stdout.decode("utf-8", "replace").splitlines()
    if not rows:
        open(args.out, "w", encoding="utf-8").close()
        return 0

    # Group words into lines by the (block, paragraph, line) tuple.
    header = rows[0].split("\t")
    index = {name: position for position, name in enumerate(header)}
    lines = {}
    order = []
    for row in rows[1:]:
        fields = row.split("\t")
        if len(fields) < len(header):
            continue
        try:
            level = int(fields[index["level"]])
            text = fields[index["text"]]
            left = int(fields[index["left"]])
            top = int(fields[index["top"]])
            width = int(fields[index["width"]])
            height = int(fields[index["height"]])
        except (ValueError, KeyError):
            continue
        if level != 5 or not text.strip():
            continue
        key = (
            fields[index["block_num"]],
            fields[index["par_num"]],
            fields[index["line_num"]],
        )
        if key not in lines:
            lines[key] = {"x0": left, "y0": top, "x1": left + width, "y1": top + height, "words": []}
            order.append(key)
        entry = lines[key]
        entry["x0"] = min(entry["x0"], left)
        entry["y0"] = min(entry["y0"], top)
        entry["x1"] = max(entry["x1"], left + width)
        entry["y1"] = max(entry["y1"], top + height)
        entry["words"].append(text)

    with open(args.out, "w", encoding="utf-8") as handle:
        for position, key in enumerate(order, start=1):
            entry = lines[key]
            x = entry["x0"]
            y = entry["y0"]
            w = entry["x1"] - entry["x0"]
            h = entry["y1"] - entry["y0"]
            text = " ".join(entry["words"])
            handle.write(f"{position}\t{x}\t{y}\t{w}\t{h}\t{text}\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    pixels = sub.add_parser("pixels")
    pixels.add_argument("--path", required=True)
    pixels.add_argument("--out", required=True)
    pixels.set_defaults(func=cmd_pixels)

    redact = sub.add_parser("redact")
    redact.add_argument("--path", required=True)
    redact.add_argument("--out", required=True)
    redact.add_argument("--boxes", required=True)
    redact.add_argument("--color", default="#000000")
    redact.set_defaults(func=cmd_redact)

    compress = sub.add_parser("compress")
    compress.add_argument("--path", required=True)
    compress.add_argument("--out", required=True)
    compress.add_argument("--max-dimension", type=int, default=2048)
    compress.set_defaults(func=cmd_compress)

    ocr = sub.add_parser("ocr")
    ocr.add_argument("--path", required=True)
    ocr.add_argument("--out", required=True)
    ocr.add_argument("--language", default="eng")
    ocr.add_argument("--tesseract", default="tesseract")
    ocr.add_argument("--timeout", type=float, default=20.0)
    ocr.set_defaults(func=cmd_ocr)

    args = parser.parse_args()
    return args.func(args) or 0


if __name__ == "__main__":
    sys.exit(main())
