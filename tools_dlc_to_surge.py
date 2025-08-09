import os, re, pathlib, datetime, collections

DLC_DIR = pathlib.Path("dlc")
DATA_DIR = DLC_DIR / "data"
OUT_DIR = pathlib.Path("surge-rules")
OUT_DIR.mkdir(parents=True, exist_ok=True)

DLC_SHA = os.environ.get("DLC_SHA","unknown")
DLC_DATE = os.environ.get("DLC_DATE", datetime.date.today().isoformat())

Rule = collections.namedtuple("Rule", "kind value attrs")  # kind: domain/full/keyword/regexp/comment ; attrs: set()

def strip_inline_comment(s: str) -> str:
    i = s.find('#')
    return (s if i < 0 else s[:i]).strip()

include_re = re.compile(r'^include:(?P<name>[A-Za-z0-9_.\-]+)$')
prefixed_re = re.compile(r'^(?P<prefix>domain|full|keyword|regexp):(?P<body>.+)$')

def parse_attrs(tokens):
    attrs, rest = set(), []
    for t in tokens:
        if t.startswith('@') and len(t) > 1:
            attrs.add(t[1:])
        elif t:
            rest.append(t)
    return rest, attrs

def parse_line(line: str):
    line = strip_inline_comment(line)
    if not line:
        return None
    m_inc = include_re.match(line)
    if m_inc:
        return ("include", m_inc.group("name"))
    m_pref = prefixed_re.match(line)
    if m_pref:
        prefix = m_pref.group("prefix")
        body = m_pref.group("body").strip()
        tokens = body.split()
        rest, attrs = parse_attrs(tokens)
        if not rest:
            return None
        return Rule(prefix, " ".join(rest), attrs)
    tokens = line.split()
    rest, attrs = parse_attrs(tokens)
    if not rest:
        return None
    return Rule("domain", " ".join(rest), attrs)

def resolve_list(name: str, stack=None, cache=None):
    if stack is None: stack = []
    if cache is None: cache = {}
    if name in cache:
        return list(cache[name])
    if name in stack:
        return [Rule("comment", f"WARNING: cyclic include: {' -> '.join(stack+[name])}", set())]
    path = DATA_DIR / name
    if not path.exists() or not path.is_file():
        return [Rule("comment", f"WARNING: include target not found: {name}", set())]
    stack.append(name)
    out = []
    with path.open("r", encoding="utf-8") as f:
        for raw in f:
            parsed = parse_line(raw)
            if not parsed:
                continue
            if isinstance(parsed, tuple) and parsed[0] == "include":
                sub = resolve_list(parsed[1], stack=stack, cache=cache)
                out.extend(sub)
            else:
                out.append(parsed)
    stack.pop()
    cache[name] = list(out)
    return out

def regexp_to_surge(pat: str):
    p = pat.strip()
    # ^(.+\.)?example\.com$ → DOMAIN,example.com + DOMAIN-WILDCARD,*.example.com
    m = re.fullmatch(r'^\^\(\.\+\\\.\)\?([A-Za-z0-9\\\.\-]+)\$$', p)
    if m:
        base = m.group(1).replace('\\.', '.')
        return [f"DOMAIN,{base}", f"DOMAIN-WILDCARD,*.{base}"]
    # ^foo\.bar$ → DOMAIN,foo.bar
    m2 = re.fullmatch(r'^\^([A-Za-z0-9\\\.\-]+)\$$', p)
    if m2:
        base = m2.group(1).replace('\\.', '.')
        return [f"DOMAIN,{base}"]
    host = p[1:] if p.startswith('^') else p
    host = host[:-1] if host.endswith('$') else host
    return [f"URL-REGEX,^https?://{host}(?::\\d+)?(?:/|$)"]

def to_surge_lines(rule: Rule):
    if rule.kind == "comment":
        return [f"# {rule.value}"]
    if rule.kind == "domain":
        return [f"DOMAIN-SUFFIX,{rule.value}"]
    if rule.kind == "full":
        return [f"DOMAIN,{rule.value}"]
    if rule.kind == "keyword":
        return [f"DOMAIN-KEYWORD,{rule.value}"]
    if rule.kind == "regexp":
        return regexp_to_surge(rule.value)
    return []

def collect_attributes(rules):
    attrs = set()
    for r in rules:
        if isinstance(r, Rule):
            attrs |= r.attrs
    return attrs

def write_ruleset(filepath: pathlib.Path, rules):
    header = [
        f"# Source: v2fly/domain-list-community",
        f"# DLC commit: {DLC_SHA} ({DLC_DATE})",
        f"# Generated at: {datetime.datetime.utcnow().isoformat()}Z",
        f"# Notes:",
        f"# - includes resolved recursively; attributes preserved.",
        f"# - regexp: best-effort → DOMAIN/DOMAIN-WILDCARD; else fallback to URL-REGEX.",
        ""
    ]
    with filepath.open("w", encoding="utf-8") as w:
        w.write("\n".join(header))
        for r in rules:
            for line in to_surge_lines(r):
                w.write(line + "\n")

def build_all():
    files = sorted(p.name for p in DATA_DIR.iterdir() if p.is_file())
    total = 0
    for name in files:
        rules = resolve_list(name)
        write_ruleset(OUT_DIR / f"{name}.list", rules)
        for attr in sorted(collect_attributes(rules)):
            filtered = [r for r in rules if isinstance(r, Rule) and (attr in r.attrs)]
            if filtered:
                write_ruleset(OUT_DIR / f"{name}@{attr}.list", filtered)
        total += 1
    print(f"Generated {total} Surge rulesets into {OUT_DIR}/")

if __name__ == "__main__":
    build_all()
