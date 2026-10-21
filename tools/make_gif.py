"""Assemble captured PNG frames into an animated GIF.

Usage:  python3 tools/make_gif.py <frames-dir> <out.gif> [delay-ms]
"""
import os
import sys

from PIL import Image


def main():
    if len(sys.argv) < 3:
        print("usage: make_gif.py <frames-dir> <out.gif> [delay-ms]")
        return 2
    frames_dir, out_path = sys.argv[1], sys.argv[2]
    delay = int(sys.argv[3]) if len(sys.argv) > 3 else 900

    names = sorted(n for n in os.listdir(frames_dir) if n.endswith(".png"))
    if not names:
        print(f"no frames in {frames_dir}")
        return 1

    images = []
    for name in names:
        im = Image.open(os.path.join(frames_dir, name)).convert("RGB")
        # GIF is palettised; keep the palette small but the colours smooth.
        im = im.quantize(colors=128, method=Image.MEDIANCUT)
        images.append(im)

    # Build a frame list with per-frame durations. Frames that barely changed
    # extend the previous frame's duration instead of being dropped, so the
    # animation holds still during pauses and still moves when something
    # actually changes.
    frames = []
    durations = []
    prev_rgb = images[0].convert("RGB")
    for idx, im in enumerate(images):
        cur_rgb = im.convert("RGB")
        pa, pb = prev_rgb.tobytes(), cur_rgb.tobytes()
        diff = sum(abs(a - b) for a, b in zip(pa, pb)) / len(pa)
        if idx == 0 or diff > 0.25:
            frames.append(im)
            durations.append(delay)
            prev_rgb = cur_rgb
        else:
            durations[-1] += delay

    frames[0].save(out_path, save_all=True, append_images=frames[1:],
                   duration=durations, loop=0, optimize=True)
    print(f"{out_path}: {len(frames)} distinct frames from {len(images)} "
          f"({sum(durations) / 1000:.1f}s total)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
