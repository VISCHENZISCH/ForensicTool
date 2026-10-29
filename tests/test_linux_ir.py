"""Tests de la chaîne de réponse à incident Linux (bodyfile, persistance, paquets, journaux)."""
from __future__ import annotations

import hashlib
import os
import struct

from forensic_analyzer.analyzers.linux import bodyfile as bf
from forensic_analyzer.analyzers.linux import logs, packages, persistence

IMPLANT = "/usr/lib/systemd/.cache/sysupdate"
UNIT = "/etc/systemd/system/systemd-sysupdate.service"
LINK = "/etc/systemd/system/multi-user.target.wants/systemd-sysupdate.service"

BODYFILE = f"""\
0|{UNIT}|151|r/rrw-rw-r--|1000|1000|195|1792572903|1792572900|1792572900|1792571535
0|{LINK} -> {UNIT}|30023|l/lrwxrwxrwx|0|0|45|1792572910|1792572908|1792572908|1792572908
0|{IMPLANT}|86|r/rrwxr-xr-x|1000|1000|764832|1792572861|1792571402|1792571535|1792571535
0|/tmp/.X11-unix/.sysupd_lock|30159|r/rrw-------|0|0|29|1|1|1|1
0|/tmp/.X11-unix|30100|d/drwxrwxrwt|0|0|4096|1|1|1|1
0|/usr/bin/ls|500|r/rrwxr-xr-x|0|0|1000|1|1|1|1
0|/usr/share/polkit-1/rules.d|600|d/drwx------|995|0|4096|1|1|1|1
0|/usr/share/old.dpkg-new (deleted-realloc)|700|r/rrw-r--r--|0|0|10|1|1|1|1
0|/etc/cron.d/.placeholder|800|r/rrw-r--r--|0|0|102|1|1|1|1
"""

UNIT_TEXT = """[Unit]
Description=System Update Helper
After=network.target

[Service]
Type=simple
ExecStart=/usr/lib/systemd/.cache/sysupdate
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""


def _write(root, rel, content: str | bytes = ""):
    path = os.path.join(root, rel.lstrip("/"))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb" if isinstance(content, bytes) else "w") as f:
        f.write(content)
    return path


def _fake_debian(root):
    """Racine Debian minimale : un paquet propre, l'unité et l'implant non déclarés."""
    ls_content = b"\x7fELF fake ls"
    _write(root, "/usr/bin/ls", ls_content)
    _write(root, "/etc/ssh/sshd_config", "PermitRootLogin no\n")
    _write(root, "/var/lib/dpkg/info/coreutils.list", "/bin/ls\n/etc/cron.d/.placeholder\n")
    _write(root, "/var/lib/dpkg/info/coreutils.md5sums",
           f"{hashlib.md5(ls_content).hexdigest()}  bin/ls\n")
    _write(root, "/var/lib/dpkg/info/openssh-server.list", "/etc/ssh/sshd_config\n")
    _write(root, "/var/lib/dpkg/status",
           "Package: openssh-server\nConffiles:\n /etc/ssh/sshd_config 00000000000000000000000000000000\n")
    _write(root, UNIT, UNIT_TEXT)
    _write(root, IMPLANT, b"\x7fELF implant")
    # tsk_recover restaure les liens symboliques en fichiers contenant la cible
    _write(root, LINK, UNIT)
    body = _write(root, "/../bodyfile.txt", BODYFILE)
    return body


def test_bodyfile_parsing_and_anomalies(tmp_path):
    body = _write(str(tmp_path), "body.txt", BODYFILE)
    entries = bf.parse_bodyfile(body)
    idx = bf.index_by_path(entries)

    assert idx[LINK].is_link and idx[LINK].link_target == UNIT
    assert idx["/usr/share/old.dpkg-new"].deleted
    assert [e.path for e in bf.ownership_anomalies(entries)] == [UNIT, IMPLANT]
    assert [e.path for e in bf.hidden_entries(entries)] == [IMPLANT, "/tmp/.X11-unix/.sysupd_lock"]


def test_systemd_unit_detection_with_bodyfile(tmp_path):
    root = str(tmp_path / "root")
    body = bf.index_by_path(bf.parse_bodyfile(_fake_debian(root)))

    result = persistence.analyze_systemd(root, body, packages.owned_paths(root))

    [unit] = [u for u in result["units"] if u["suspicious"]]
    assert unit["unit"] == UNIT and unit["owner_uid"] == 1000
    assert unit["enabled_by"][0]["created"] == "2026-10-21T08:55:08+00:00"
    assert {"T1543.002", "T1564.001", "T1036.005"} <= set(unit["mitre"])
    assert any("Restart=always" in r for r in unit["reasons"])


def test_systemd_detection_without_bodyfile_ignores_restored_links(tmp_path):
    root = str(tmp_path / "root")
    _fake_debian(root)
    result = persistence.analyze_systemd(root, None, packages.owned_paths(root))
    assert [u["unit"] for u in result["units"]] == [UNIT]
    assert result["units"][0]["suspicious"]


def test_legitimate_unit_is_not_suspicious(tmp_path):
    root = str(tmp_path)
    _write(root, "/etc/systemd/system/backup.service",
           "[Service]\nExecStart=/usr/bin/rsync -a /srv /backup\nUser=backup\n")
    [unit] = persistence.analyze_systemd(root)["units"]
    assert not unit["suspicious"]


def test_other_persistence_locations(tmp_path):
    root = str(tmp_path)
    _write(root, "/etc/ld.so.preload", "/lib/x86_64-linux-gnu/libevil.so\n")
    _write(root, "/root/.ssh/authorized_keys", "ssh-ed25519 AAAA attacker\n")
    _write(root, "/etc/cron.d/.placeholder", "")
    _write(root, "/etc/cron.d/backdoor", "* * * * * root /tmp/x\n")
    found = {f["path"]: f for f in persistence.other_persistence(root, owned=set())}
    assert found["/etc/ld.so.preload"]["mitre"] == "T1574.006"
    assert found["/root/.ssh/authorized_keys"]["detail"] == "1 clé(s)"
    assert "/etc/cron.d/backdoor" in found and "/etc/cron.d/.placeholder" not in found


def test_dpkg_verification_and_files_outside_packages(tmp_path):
    root = str(tmp_path / "root")
    entries = bf.parse_bodyfile(_fake_debian(root))

    report = packages.verify_dpkg(root, bf.index_by_path(entries))
    assert report["checked"] == 2 and report["conffiles"] == 1
    assert report["ok"] == 1  # /bin/ls lu sous /usr (merged-usr)
    assert [m["path"] for m in report["modified"]] == ["/etc/ssh/sshd_config"]

    outside = packages.files_outside_packages(root, entries, bf.PACKAGE_PREFIXES)
    assert [e.path for e in outside] == [UNIT, IMPLANT]


def test_audit_log_parsing(tmp_path):
    audit = _write(str(tmp_path), "audit.log", (
        "type=USER_AUTH msg=audit(1792572691.140:35): pid=317 uid=0 msg='op=PAM:authentication "
        "grantors=pam_permit acct=\"root\" exe=\"/usr/bin/login\" terminal=/dev/ttyS0 res=success'\n"
        "type=USER_AUTH msg=audit(1792572692.000:36): pid=318 uid=0 msg='op=PAM:authentication "
        "acct=\"bob\" exe=\"/usr/sbin/sshd\" res=failed'\n"
        "type=SERVICE_START msg=audit(1792572877.824:9): pid=1 msg='unit=systemd-sysupdate res=success'\n"
    ))
    result = logs.parse_audit_log(audit)
    assert result["auth"][0]["acct"] == "root" and result["auth"][0]["terminal"] == "/dev/ttyS0"
    assert result["auth"][0]["time"] == "2026-10-21T08:51:31.140000+00:00"
    assert result["auth_failures"][0]["acct"] == "bob"
    assert result["services"][0]["unit"] == "systemd-sysupdate"
    assert result["execve_events"] == 0


def _utmp(kind: int, line: str, user: str, ts: int) -> bytes:
    rec = bytearray(384)
    struct.pack_into("<h", rec, 0, kind)
    rec[8:8 + len(line)] = line.encode()
    rec[44:44 + len(user)] = user.encode()
    struct.pack_into("<i", rec, 340, ts)
    return bytes(rec)


def test_wtmp_and_lastlog_parsing(tmp_path):
    wtmp = _write(str(tmp_path), "wtmp",
                  _utmp(2, "~", "reboot", 1792571581) + _utmp(8, "", "", 1) + _utmp(7, "ttyS0", "root", 1792572691))
    records = logs.parse_wtmp(wtmp)
    assert [(r["type"], r["user"]) for r in records] == [("BOOT", "reboot"), ("USER", "root")]
    assert records[1]["time"] == "2026-10-21T08:51:31+00:00"

    lastlog = bytearray(292 * 2)
    struct.pack_into("<i", lastlog, 292, 1792572691)
    lastlog[296:301] = b"ttyS0"
    entries = logs.parse_lastlog(_write(str(tmp_path), "lastlog", bytes(lastlog)))
    assert entries == [{"uid": 1, "time": "2026-10-21T08:51:31+00:00", "line": "ttyS0", "host": ""}]
