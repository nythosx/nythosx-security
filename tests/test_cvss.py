from engine.cvss import cvss_vector_to_score, score_to_severity


def test_v3_critical():
    score = cvss_vector_to_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8
    assert score_to_severity(score) == "critical"


def test_v3_medium():
    score = cvss_vector_to_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N")
    assert score == 4.8
    assert score_to_severity(score) == "medium"


def test_v3_high():
    score = cvss_vector_to_score("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H")
    assert score is not None
    assert score >= 8.0
    assert score_to_severity(score) == "high"


def test_v3_scope_changed():
    score = cvss_vector_to_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N")
    assert score is not None
    assert score > 0


def test_v3_no_prefix():
    score = cvss_vector_to_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert score == 9.8


def test_v3_missing_metric():
    assert cvss_vector_to_score("CVSS:3.1/AV:N/AC:L") is None


def test_v3_zero_impact():
    score = cvss_vector_to_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N")
    assert score == 0.0
    assert score_to_severity(score) == "none"


def test_v2_max():
    score = cvss_vector_to_score("AV:N/AC:L/Au:N/C:C/I:C/A:C")
    assert score == 10.0


def test_v2_medium():
    score = cvss_vector_to_score("AV:L/AC:H/Au:S/C:P/I:P/A:P")
    assert score == 3.5


def test_v2_zero_impact():
    score = cvss_vector_to_score("AV:N/AC:L/Au:N/C:N/I:N/A:N")
    assert score == 0.0


def test_none_and_empty():
    assert cvss_vector_to_score(None) is None
    assert cvss_vector_to_score("") is None


def test_garbage():
    assert cvss_vector_to_score("not a vector") is None


def test_severity_bands():
    assert score_to_severity(0.0) == "none"
    assert score_to_severity(3.9) == "low"
    assert score_to_severity(4.0) == "medium"
    assert score_to_severity(6.9) == "medium"
    assert score_to_severity(7.0) == "high"
    assert score_to_severity(8.9) == "high"
    assert score_to_severity(9.0) == "critical"
    assert score_to_severity(10.0) == "critical"
    assert score_to_severity(None) == "unknown"
