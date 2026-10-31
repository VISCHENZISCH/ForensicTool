"""Mise à jour : décision sur git rev-list, refus si le dépôt local a bougé."""
from __future__ import annotations

import shutil
import subprocess

import pytest

pytestmark = pytest.mark.skipif(not shutil.which("git"), reason="git absent")


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=cwd, check=True,
                   capture_output=True, env={"LANG": "fr_FR.UTF-8", "PATH": "/usr/bin:/bin", "HOME": str(cwd)})


@pytest.fixture
def repos(tmp_path, monkeypatch):
    from forensic_analyzer.core import updater

    upstream, local = tmp_path / "upstream", tmp_path / "local"
    upstream.mkdir()
    _git(upstream, "init", "-q", "-b", "main")
    (upstream / "f.txt").write_text("v1")
    _git(upstream, "add", ".")
    _git(upstream, "commit", "-qm", "v1")
    _git(tmp_path, "clone", "-q", str(upstream), str(local))
    (upstream / "f.txt").write_text("v2")
    _git(upstream, "commit", "-qam", "v2")
    monkeypatch.setattr(updater, "_REPO", str(local))
    return upstream, local


def test_update_is_applied_when_behind(repos, capsys):
    from forensic_analyzer.core.updater import Updater

    Updater().check_and_update()
    assert (repos[1] / "f.txt").read_text() == "v2"
    Updater().check_and_update()
    assert "déjà à jour" in capsys.readouterr().out


def test_update_is_refused_over_local_changes(repos, capsys):
    from forensic_analyzer.core.updater import Updater

    (repos[1] / "f.txt").write_text("modifié par l'analyste")
    Updater().check_and_update()
    assert "refusée" in capsys.readouterr().out
    assert (repos[1] / "f.txt").read_text() == "modifié par l'analyste"
