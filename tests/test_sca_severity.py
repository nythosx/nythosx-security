from engine.sca import _severity_from_vuln


def test_v3_critical_vector():
    vuln = {"severity": [{"score":
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}
    assert _severity_from_vuln(vuln) == "critical"


def test_v3_high_vector():
    vuln = {"severity": [{"score":
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"}]}
    assert _severity_from_vuln(vuln) == "high"


def test_v3_medium_vector():
    vuln = {"severity": [{"score":
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N"}]}
    assert _severity_from_vuln(vuln) == "medium"


def test_v2_max_vector():
    vuln = {"severity": [{"score": "AV:N/AC:L/Au:N/C:C/I:C/A:C"}]}
    assert _severity_from_vuln(vuln) == "critical"


def test_unparseable_vector_returns_unknown():
    vuln = {"severity": [{"score": "CVSS:4.0/SOMETHING-ELSE"}]}
    assert _severity_from_vuln(vuln) == "unknown"


def test_no_vector_falls_back_to_database_specific():
    vuln = {"database_specific": {"severity": "HIGH"}}
    assert _severity_from_vuln(vuln) == "high"


def test_no_severity_at_all_returns_medium():
    assert _severity_from_vuln({}) == "medium"
