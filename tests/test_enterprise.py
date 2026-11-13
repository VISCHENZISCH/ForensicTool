"""Usage en entreprise : chaîne de possession, export SIEM (ECS), MISP, configuration, journal JSON, codes de sortie."""

from __future__ import annotations

import hashlib
import json
import logging
import pathlib
import subprocess  # nosec B404
import sys

import pytest

from forensic_analyzer.cli.main import EXIT_USAGE, build_parser, custody_fields, parse_arguments
from forensic_analyzer.models.finding import AnalysisError, FindingModel, ReportModel, fingerprint
from forensic_analyzer.output.ecs_exporter import ECS_VERSION, ECSExporter, ecs_documents
from forensic_analyzer.output.misp_exporter import MISPExporter, misp_event
from forensic_analyzer.utils.config import ConfigError, load_config
from forensic_analyzer.utils.logger import disable_json_log, enable_json_log, get_logger, log_event, redact

# Valeurs autorisées par ECS 8.x (elastic.co, « ECS Categorization Fields »)
ECS_KINDS = {"alert", "asset", "enrichment", "event", "metric", "state", "pipeline_error", "signal"}
ECS_CATEGORIES = {
    "api", "authentication", "configuration", "database", "driver", "email", "file", "host", "iam",
    "intrusion_detection", "library", "malware", "network", "package", "process", "registry", "session",
    "threat", "vulnerability", "web",
}  # fmt: skip
ECS_TYPES = {
    "access", "admin", "allowed", "change", "connection", "creation", "deletion", "denied", "end", "error",
    "group", "indicator", "info", "installation", "protocol", "start", "user",
}  # fmt: skip


def _report(tmp_path) -> ReportModel:
    evidence = tmp_path / "preuve.exe"
    evidence.write_bytes(b"MZ" + b"\0" * 64)
    alert = FindingModel(
        type="malware_analysis",
        file=str(evidence),
        metadata={"[ALERTE] Injection": "VirtualAllocEx + WriteProcessMemory", "C2": "198.51.100.9"},
        extra={
            "mitre": [{"id": "T1055", "name": "Process Injection", "tactic": "Évasion"}],
            "timeline_events": [
                {
                    "timestamp": "2026-10-10T13:55:36+00:00",
                    "source": "auth.log",
                    "event_type": "Connexion SSH acceptée",
                    "description": "Accepted password for root",
                    "ip": "203.0.113.7",
                    "user": "root",
                },
                {"timestamp": "pas une date", "source": "x", "description": "écarté"},
            ],
        },
        severity="critique",
    )
    benign = FindingModel(type="correlation", file="multi-source", metadata={"note": "rien"}, severity="info")
    return ReportModel.from_findings(
        [alert, benign],
        analysis_errors=[AnalysisError(module="pdf", file="/x.pdf", error="ValueError", message="chiffré")],
        evidence=[fingerprint(str(evidence))],
        case_id="INC-2026-042",
        examiner="j.dupont",
        organization="CERT Test",
        started_at="2026-11-12T10:00:00+00:00",
        finished_at="2026-11-12T10:05:00+00:00",
        command_line=["forensic-analyzer", "--scan", "x"],
    )


# --- Chaîne de possession -------------------------------------------------------------------


def test_report_carries_custody_fields(tmp_path):
    data = json.loads(_report(tmp_path).model_dump_json())
    assert data["case_id"] == "INC-2026-042"
    assert (data["examiner"], data["organization"]) == ("j.dupont", "CERT Test")
    assert data["analysis_host"] and data["tool"].startswith("Forensic Analyzer")
    assert data["started_at"] < data["finished_at"]
    assert data["command_line"][0] == "forensic-analyzer"
    assert data["evidence"][0]["sha256"] == hashlib.sha256(b"MZ" + b"\0" * 64).hexdigest()


def test_custody_defaults_keep_old_reports_valid():
    report = ReportModel.from_findings([])
    assert report.case_id is None and report.command_line == []
    assert report.analysis_host  # toujours renseigné : la machine d'analyse fait partie de la traçabilité


def test_command_line_is_recorded_with_secrets_masked():
    args = build_parser().parse_args(["--scan", "x", "--case-id", "C1"])
    custody = custody_fields(args, ["--scan", "x", "--case-id", "C1", "token=abcdef123"])
    assert custody["case_id"] == "C1" and custody["started_at"].endswith("+00:00")
    assert custody["command_line"][-1] == "token=***"


# --- Export ECS -----------------------------------------------------------------------------


def test_ecs_export_is_valid_ndjson(tmp_path):
    path = ECSExporter().export(_report(tmp_path), str(tmp_path / "out" / "siem.ndjson"))
    lines = open(path, encoding="utf-8").read().splitlines()
    docs = [json.loads(line) for line in lines]  # chaque ligne est un document JSON autonome
    assert docs and all(line.startswith("{") for line in lines)
    for doc in docs:
        assert doc["@timestamp"].endswith("Z")
        assert doc["ecs"]["version"] == ECS_VERSION and ECS_VERSION.startswith("8.")
        assert doc["event"]["kind"] in ECS_KINDS
        assert set(doc["event"]["category"]) <= ECS_CATEGORIES
        assert set(doc["event"]["type"]) <= ECS_TYPES
        assert doc["event"]["module"] == "forensic_analyzer"
        assert doc["labels"]["case_id"] == "INC-2026-042"
        assert doc["observer"]["version"].startswith("Forensic Analyzer")


def test_ecs_alert_maps_mitre_hashes_and_risk(tmp_path):
    docs = ecs_documents(_report(tmp_path))
    (alert,) = [d for d in docs if d["event"]["kind"] == "alert" and d["event"]["dataset"].endswith("finding")]
    assert alert["threat"]["framework"] == "MITRE ATT&CK"
    assert alert["threat"]["technique"]["id"] == ["T1055"]
    assert alert["file"]["hash"]["sha256"] == hashlib.sha256(b"MZ" + b"\0" * 64).hexdigest()
    assert alert["event"]["risk_score"] == 99 and alert["rule"]["name"] == "malware_analysis"
    assert "Injection" in alert["message"]


def test_ecs_timeline_evidence_and_errors(tmp_path):
    docs = ecs_documents(_report(tmp_path))
    by_dataset: dict[str, list] = {}
    for d in docs:
        by_dataset.setdefault(d["event"]["dataset"], []).append(d)
    timeline = by_dataset["forensic_analyzer.timeline"]
    assert all("écarté" not in d["message"] for d in timeline)  # sans date lisible : pas de document
    (ssh,) = [d for d in timeline if d["event"]["provider"] == "auth.log"]
    assert ssh["@timestamp"] == "2026-10-10T13:55:36.000Z"
    assert ssh["source"]["ip"] == "203.0.113.7" and ssh["user"]["name"] == "root"
    assert ssh["event"]["category"] == ["authentication"]
    assert by_dataset["forensic_analyzer.evidence"][0]["file"]["hash"]["sha256"]
    assert by_dataset["forensic_analyzer.error"][0]["event"]["outcome"] == "failure"
    # un constat transverse n'est pas un fichier
    (corr,) = [d for d in by_dataset["forensic_analyzer.finding"] if d["event"]["provider"] == "correlation"]
    assert "file" not in corr


# --- Export MISP ----------------------------------------------------------------------------


def test_misp_event_is_offline_file_with_iocs(tmp_path):
    report = _report(tmp_path)
    path = MISPExporter().export(report, str(tmp_path / "out" / "iocs.misp.json"))
    event = json.load(open(path, encoding="utf-8"))["Event"]
    assert event["published"] is False and event["distribution"] == "0"  # le partage reste une décision humaine
    assert event["threat_level_id"] == "1" and "INC-2026-042" in event["info"]
    assert {"name": "tlp:amber"} in event["Tag"]
    assert any(t["name"].endswith('"Process Injection - T1055"') for t in event["Tag"])
    hashes = [a for a in event["Attribute"] if a["type"] == "sha256"]
    assert hashes and hashes[0]["to_ids"] is True
    # mêmes UUID à chaque export de la même affaire : MISP fusionne au lieu de dupliquer
    assert misp_event(report)["Event"]["Attribute"][0]["uuid"] == event["Attribute"][0]["uuid"]


# --- Configuration --------------------------------------------------------------------------


def _config(tmp_path, body: str):
    path = tmp_path / "fa.toml"
    path.write_text(body, encoding="utf-8")
    return str(path)


def test_config_provides_defaults_and_cli_overrides(tmp_path):
    cfg = _config(tmp_path, '[defaults]\nexaminer = "conf"\norganization = "CERT"\nexport-dir = "/srv/x"\nquiet = true\n')
    args = parse_arguments(build_parser(), ["--scan", "x", "--config", cfg, "--examiner", "cli"])
    assert args.examiner == "cli"  # la ligne de commande l'emporte
    assert (args.organization, args.export_dir, args.quiet) == ("CERT", "/srv/x", True)


def test_config_from_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("FORENSIC_ANALYZER_CONFIG", _config(tmp_path, '[defaults]\ncase_id = "ENV-1"\n'))
    assert parse_arguments(build_parser(), ["--scan", "x"]).case_id == "ENV-1"


@pytest.mark.parametrize(
    "body",
    [
        "[defaults]\nonline = true\n",  # le réseau reste une décision explicite, jamais une valeur par défaut
        '[defaults]\nquiet = "oui"\n',
        "[defaults\n",
    ],
)
def test_invalid_config_is_refused(tmp_path, body):
    with pytest.raises(ConfigError):
        load_config(_config(tmp_path, body))


def test_invalid_config_exits_with_usage_code(tmp_path):
    with pytest.raises(SystemExit) as exc:
        parse_arguments(build_parser(), ["--scan", "x", "--config", _config(tmp_path, "[defaults]\nonline = true\n")])
    assert exc.value.code == EXIT_USAGE


def test_bad_option_does_not_mean_altered_evidence(capsys):
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args(["--option-inexistante"])
    assert exc.value.code == EXIT_USAGE != 2


# --- Journal d'exécution JSON ---------------------------------------------------------------


def test_json_log_lines_and_secret_redaction(tmp_path, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "cle-secrete-123456")
    handler = enable_json_log(str(tmp_path / "logs" / "run.jsonl"))
    try:
        get_logger("test_entreprise").info("appel avec cle-secrete-123456 et api_key=zzz999")
        log_event("run_end", "Fin", exit_code=3, case_id="C1")
    finally:
        disable_json_log(handler)
    text = (tmp_path / "logs" / "run.jsonl").read_text(encoding="utf-8")
    assert "cle-secrete-123456" not in text and "zzz999" not in text
    lines = [json.loads(line) for line in text.splitlines()]
    assert lines[0]["log.level"] == "info" and lines[0]["@timestamp"].endswith("Z")
    assert lines[1]["event.action"] == "run_end" and lines[1]["exit_code"] == 3
    logging.getLogger("forensic.test_entreprise").info("après fermeture")  # le journal n'est plus alimenté
    assert len((tmp_path / "logs" / "run.jsonl").read_text(encoding="utf-8").splitlines()) == 2


def test_redact_leaves_ordinary_text():
    assert redact("Analyse du journal access.log") == "Analyse du journal access.log"


# --- Bout en bout (batch) -------------------------------------------------------------------


def test_batch_run_end_to_end(tmp_path):
    log_file = tmp_path / "access.log"
    line = '203.0.113.7 - - [10/Oct/2026:13:55:36 +0000] "GET /?id=1%27%20UNION%20SELECT%201-- HTTP/1.1" 200 5 "-" "sqlmap/1.7"\n'
    log_file.write_text(line * 30, encoding="utf-8")
    cfg = _config(tmp_path, '[defaults]\norganization = "CERT Test"\nquiet = true\n')
    before = hashlib.sha256(log_file.read_bytes()).hexdigest()
    run = subprocess.run(  # nosec B603
        [sys.executable, "-m", "forensic_analyzer.cli.main", "--logs", str(log_file), "--config", cfg,
         "--case-id", "INC/9", "--examiner", "j.dupont", "--log-json", str(tmp_path / "run.jsonl"),
         "--export-ecs", "siem.ndjson", "--export-json", "r.json", "--export-dir", str(tmp_path / "out")],
        capture_output=True, text=True, cwd=tmp_path, timeout=300,
        env={"PYTHONPATH": str(pathlib.Path(__file__).parents[1]), "PATH": "/usr/bin:/bin"},
    )  # fmt: skip
    assert run.returncode == 3, run.stderr  # menace élevée : code de sortie conservé
    assert "code de sortie 3" in run.stderr  # synthèse batch d'une ligne
    assert hashlib.sha256(log_file.read_bytes()).hexdigest() == before  # preuve intacte
    report = json.loads((tmp_path / "out" / "r.json").read_text(encoding="utf-8"))
    assert (report["case_id"], report["examiner"], report["organization"]) == ("INC/9", "j.dupont", "CERT Test")
    manifest = (tmp_path / "out" / "exports.sha256").read_text(encoding="utf-8").splitlines()
    assert len(manifest) == 2
    for entry in manifest:
        digest, path = entry.split("  ", 1)
        assert hashlib.sha256(open(path, "rb").read()).hexdigest() == digest
    events = [json.loads(x) for x in (tmp_path / "run.jsonl").read_text(encoding="utf-8").splitlines()]
    actions = [e.get("event.action") for e in events]
    assert actions[0] == "run_start" and actions[-1] == "run_end"
    assert events[-1]["exit_code"] == 3 and events[-1]["export_manifest"].endswith("exports.sha256")


def test_missing_evidence_is_a_usage_error(tmp_path):
    import pytest

    from forensic_analyzer.cli.main import EXIT_USAGE, cli_dispatch

    with pytest.raises(SystemExit) as exc:
        cli_dispatch(["--scan", str(tmp_path / "absente.tar.gz"), "--quiet"])
    assert exc.value.code == EXIT_USAGE
