import json
from pathlib import Path

from cloudsentry.cli import main

FIXTURES = Path(__file__).parent / "fixtures"
FAULTS = str(FIXTURES / "plan-faults.json")
CLEAN = str(FIXTURES / "plan-clean.json")


def test_seeded_faults_are_all_detected(capsys):
    assert main(["scan", "--plan", FAULTS, "--expect"]) == 0
    out = capsys.readouterr().out
    assert "10 findings (6 high, 3 medium, 1 low)" in out
    assert "Seeded faults detected: 10/10, missed 0, unexpected findings 0" in out


def test_clean_plan_passes_a_strict_gate(capsys):
    assert main(["scan", "--plan", CLEAN, "--expect", "--fail-on", "low"]) == 0
    assert "0 findings" in capsys.readouterr().out


def test_fail_on_high_fails_the_faulty_plan():
    assert main(["scan", "--plan", FAULTS, "--fail-on", "high"]) == 1


def test_a_finding_without_a_fault_tag_counts_as_unexpected(tmp_path, capsys):
    plan = json.loads(Path(FAULTS).read_text())
    for resource in plan["planned_values"]["root_module"]["resources"]:
        if resource["address"] == "aws_vpc.b":
            del resource["values"]["tags_all"]["Fault"]
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(plan))
    assert main(["scan", "--plan", str(path), "--expect"]) == 1
    assert "unexpected: CIS 3.7 on aws_vpc.b" in capsys.readouterr().out


def test_json_and_markdown_output(tmp_path, capsys):
    out_file = tmp_path / "findings.json"
    main(["scan", "--plan", FAULTS, "--json", str(out_file), "--markdown"])
    data = json.loads(out_file.read_text())
    assert len(data["findings"]) == 10
    assert {"control", "severity", "resource", "region", "detail"} <= set(data["findings"][0])
    assert "| CIS 5.2 | high | `aws_network_acl.noreturn[0]` |" in capsys.readouterr().out


def fake_probe(open_pairs):
    def run(targets):
        return {target: target in open_pairs for target in targets}

    return run


def test_exposure_scores_both_checks_against_probes(lab, monkeypatch, tmp_path, capsys):
    ips = {i.name.removeprefix("cloudsentry-"): i.public_ip for i in lab.instances}
    reachable = {(ips["open-ssh"], 22), (ips["open-rdp"], 3389), (ips["all-open"], 22), (ips["all-open"], 3389)}
    monkeypatch.setattr("cloudsentry.collect_aws.collect", lambda *args: lab)
    monkeypatch.setattr("cloudsentry.probe.preflight", lambda ports: dict.fromkeys(ports, True))
    monkeypatch.setattr("cloudsentry.probe.probe", fake_probe(reachable))
    out = tmp_path / "exposure.json"

    assert main(["exposure", "--source", "192.0.2.10", "--probe", "--out", str(out)]) == 0
    text = capsys.readouterr().out
    assert "security group only: flagged 8, confirmed by probe 4, false positives 4, missed 0" in text
    assert "full path: flagged 4, confirmed by probe 4, false positives 0, missed 0" in text

    record = json.loads(out.read_text())
    assert len(record["pairs"]) == 16
    assert "203.0.113" not in out.read_text()  # addresses are not saved


def test_exposure_stops_when_the_local_network_blocks_a_port(lab, monkeypatch, capsys):
    monkeypatch.setattr("cloudsentry.collect_aws.collect", lambda *args: lab)
    monkeypatch.setattr("cloudsentry.probe.preflight", lambda ports: {22: True, 3389: False})
    assert main(["exposure", "--source", "192.0.2.10", "--probe"]) == 2
    assert "blocks outbound TCP 3389" in capsys.readouterr().out


def test_exposure_fails_when_a_probe_disagrees(lab, monkeypatch):
    monkeypatch.setattr("cloudsentry.collect_aws.collect", lambda *args: lab)
    monkeypatch.setattr("cloudsentry.probe.preflight", lambda ports: dict.fromkeys(ports, True))
    monkeypatch.setattr("cloudsentry.probe.probe", fake_probe(set()))
    assert main(["exposure", "--source", "192.0.2.10", "--probe"]) == 1
