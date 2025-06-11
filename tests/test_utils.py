import os
import pytest

try:
    from PIL import Image, PngImagePlugin
    PIL_AVAILABLE = True
except ModuleNotFoundError:
    PIL_AVAILABLE = False

from core import utils


def test_hash_text():
    assert utils.hash_text("abc", "sha256") == utils.hash_text("abc")


def test_get_password():
    pw = utils.get_password(length=8, use_nums=False, use_specials=False)
    assert len(pw) == 8
    assert pw.isalpha()

    pw_num = utils.get_password(length=5, use_chars=False, use_nums=True, use_specials=False)
    assert pw_num.isdigit()

    with pytest.raises(ValueError):
        utils.get_password(4, use_chars=False, use_nums=False, use_specials=False)


def test_hash_file(tmp_path):
    file_path = tmp_path / "sample.txt"
    file_path.write_text("hello")
    result = utils.hash_file(str(file_path))
    assert len(result) > 0


def test_ensure_themes(tmp_path, monkeypatch):
    temp_data = tmp_path / "data"
    monkeypatch.setattr(utils, "THEME_PATH", temp_data / "themes.ini")
    utils.ensure_themes()
    assert os.path.exists(utils.THEME_PATH)
    themes = utils.load_themes()
    expected = {'dark', 'light', 'dark_blue', 'matrix', 'sunset', 'ocean', 'pastel'}
    assert expected.issubset(themes.keys())
    for th in themes.values():
        assert 'tab_background' in th
        assert 'text_foreground' in th
        assert 'dropdown_background' in th
        assert 'dropdown_foreground' in th


def test_strip_metadata(tmp_path):
    src = tmp_path / "orig.txt"
    src.write_text("hello")
    dest = tmp_path / "new.txt"
    utils.strip_metadata(str(src), str(dest))
    assert dest.read_text() == "hello"


def _make_png_with_text(path):
    import struct, zlib

    def chunk(typ, data):
        return (
            struct.pack(">I", len(data))
            + typ
            + data
            + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)
        )

    raw = b"\x00\xff\x00\x00"  # one red pixel
    with open(path, "wb") as f:
        f.write(b"\x89PNG\r\n\x1a\n")
        f.write(chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)))
        f.write(chunk(b"IDAT", zlib.compress(raw)))
        f.write(chunk(b"tEXt", b"Title\x00Hello"))
        f.write(chunk(b"IEND", b""))


def _read_png_chunks(path):
    import struct
    with open(path, "rb") as f:
        data = f.read()
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    idx = 8
    chunks = []
    while idx + 8 <= len(data):
        length = int.from_bytes(data[idx : idx + 4], "big")
        ctype = data[idx + 4 : idx + 8]
        chunks.append(ctype)
        idx += 8 + length + 4
        if ctype == b"IEND":
            break
    return chunks


def test_strip_metadata_png(tmp_path):
    src = tmp_path / "orig.png"
    _make_png_with_text(src)

    dest = tmp_path / "clean.png"
    utils.strip_metadata(str(src), str(dest))

    chunks = _read_png_chunks(dest)
    assert b"tEXt" not in chunks
    assert b"iTXt" not in chunks
    assert b"zTXt" not in chunks


def test_save_metadata_text(tmp_path):
    src = tmp_path / "orig.txt"
    src.write_text("hello")
    dest = tmp_path / "meta.txt"
    utils.save_metadata(str(src), str(dest))
    assert dest.exists()
    assert "No metadata" in dest.read_text()


@pytest.mark.skipif(not PIL_AVAILABLE, reason="Pillow not installed")
def test_save_metadata_png(tmp_path):
    img = Image.new("RGB", (1, 1), color="red")
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "tester")
    src = tmp_path / "img.png"
    img.save(src, pnginfo=meta)

    dest = tmp_path / "img_meta.txt"
    utils.save_metadata(str(src), str(dest))
    text = dest.read_text()
    assert "Author" in text
