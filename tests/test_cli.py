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
