import os
import pytest

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
    assert 'dark' in themes and 'light' in themes
    for th in themes.values():
        assert 'tab_background' in th
        assert 'text_foreground' in th
