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


@pytest.mark.skipif(not PIL_AVAILABLE, reason="Pillow not installed")
def test_strip_metadata_png(tmp_path):
    img = Image.new("RGB", (1, 1), color="red")
    meta = PngImagePlugin.PngInfo()
    meta.add_text("Author", "tester")
    src = tmp_path / "orig.png"
    img.save(src, pnginfo=meta)

    dest = tmp_path / "clean.png"
    utils.strip_metadata(str(src), str(dest))

    with Image.open(dest) as out_img:
        assert "Author" not in out_img.info


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
