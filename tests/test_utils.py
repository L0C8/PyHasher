import os

from core import utils


def test_hash_text():
    assert utils.hash_text("abc", "sha256") == utils.hash_text("abc")


def test_get_password():
    pw = utils.get_password(length=8)
    assert len(pw) == 8


def test_ensure_themes(tmp_path, monkeypatch):
    temp_data = tmp_path / "data"
    monkeypatch.setattr(utils, "THEME_PATH", temp_data / "themes.ini")
    utils.ensure_themes()
    assert os.path.exists(utils.THEME_PATH)
