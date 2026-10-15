"""Explicit clean-room conversion. Run before hashing/signing, never during verify."""
from pathlib import Path
import os
import tempfile
import wave


def clean_asset(source: str, output: str) -> str:
    """Write a metadata-free PNG or PCM WAV, preserving pixels or PCM frames.

    PNG requires the ``images`` extra. Animated and high-bit-depth PNGs are
    rejected rather than silently flattened or reduced. Other formats raise
    ValueError. Output is replaced atomically after successful conversion.
    """
    source_path, output_path = Path(source), Path(output)
    kind = source_path.suffix.lower()
    if kind not in (".png", ".wav") or output_path.suffix.lower() != kind:
        raise ValueError("clean_asset supports matching .png or .wav input/output only")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=output_path.parent, suffix=kind)
    os.close(fd)
    try:
        if kind == ".png":
            from PIL import Image
            with Image.open(source_path) as original:
                if original.format != "PNG" or getattr(original, "n_frames", 1) != 1:
                    raise ValueError("only single-frame PNG assets are supported")
                # PNG IHDR bit depth is byte 24. Pillow can downconvert 16-bit RGB.
                with open(source_path, "rb") as stream:
                    header = stream.read(25)
                if len(header) < 25 or header[24] > 8:
                    raise ValueError("high-bit-depth PNG assets are not supported")
                original.load()
                transparency = original.info.get("transparency")
                clean = original.copy()
                clean.info.clear()
                options = {} if transparency is None else {"transparency": transparency}
                clean.save(temporary, format="PNG", **options)
        else:
            with wave.open(str(source_path), "rb") as original:
                if original.getcomptype() != "NONE":
                    raise ValueError("only PCM WAV assets are supported")
                with wave.open(temporary, "wb") as clean:
                    clean.setparams(original.getparams())
                    while True:
                        frames = original.readframes(65536)
                        if not frames:
                            break
                        clean.writeframesraw(frames)
        os.replace(temporary, output_path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return str(output_path)
