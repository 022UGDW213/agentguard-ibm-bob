from agentguard.scanner import scan_all, scan_secrets


def test_secret_scan_finds_known_patterns(tmp_path):
    dirty = tmp_path / "config.py"
    dirty.write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'token = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"\n'
    )
    clean = tmp_path / "main.py"
    clean.write_text('print("hello")\n')
    count, findings = scan_secrets(tmp_path)
    assert count == 2
    kinds = {f.kind for f in findings}
    assert kinds == {"aws_access_key", "github_token"}
    assert all(f.file.endswith("config.py") for f in findings)


def test_secret_scan_skips_git_and_binary(tmp_path):
    gitdir = tmp_path / ".git"
    gitdir.mkdir()
    (gitdir / "objects").write_text("AKIAIOSFODNN7EXAMPLE")
    count, findings = scan_secrets(tmp_path)
    assert count == 0
    assert findings == []


def test_scan_all_report_shape(tmp_path):
    (tmp_path / "app.py").write_text("x = 1\n")
    report = scan_all(tmp_path)
    d = report.to_dict()
    assert d["root"] == str(tmp_path)
    assert d["files_scanned"] == 1
    assert d["secrets"] == []
    assert isinstance(d["dependency_checks"], list)
    # No requirements.txt / package-lock.json -> both skipped honestly
    assert all(c["status"] == "skipped" for c in d["dependency_checks"])
