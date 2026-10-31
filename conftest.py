import pytest


@pytest.fixture(autouse=True)
def _log(tmp_path, monkeypatch):
    monkeypatch.setenv("DENYLIST_HOOK_LOG", str(tmp_path / "denylist.log"))
