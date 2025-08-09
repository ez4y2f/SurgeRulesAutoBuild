import os, re, pathlib, datetime, collections

DLC_DIR = pathlib.Path("dlc")
DATA_DIR = DLC_DIR / "data"
OUT_DIR = pathlib.Path("surge-rules")
OUT_DIR.mkdir(parents=True, exist_ok=True)

DLC_SHA = os.environ.get("DLC_SHA","unknown")
DLC_DATE = os.environ.get("DLC_DATE", datetime.date.today().isoformat())
USE_WILDCARD = os.environ.get("USE_WILDCARD","false").lower() == "true"
ALLOW_COMMENTS = os.environ.get("ALLOW_COMMENTS","false").lower() == "true"

Rule = collections.namedtuple("Rule", "kind value attrs")

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
    line = line.replace('\ufeff','')
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
                out.extend(resolve_list(parsed[1], stack=stack, cache=cache))
            else:
                out.append(parsed)
    stack.pop()
    cache[name] = list(out)
    return out

VAL_DOMAIN = r'[A-Za-z0-9.-]+'
STRICT_PATTERNS = [
    re.compile(r'^DOMAIN,' + VAL_DOMAIN + r'$'),
    re.compile(r'^DOMAIN-SUFFIX,' + VAL_DOMAIN + r'$'),
    re.compile(r'^DOMAIN-KEYWORD,[^,\s]+$'),
    re.compile(r'^URL-REGEX,.+$'),
]
if USE_WILDCARD:
    STRICT_PATTERNS.append(re.compile(r'^DOMAIN-WILDCARD,\*\.(' + VAL_DOMAIN + r')$'))

def valid_line(s: str) -> bool:
    for pat in STRICT_PATTERNS:
        if pat.match(s):
            return True
    return False

def regexp_to_surge(pat: str):
    p = pat.strip()
    out = []
    m = re.fullmatch(r'^\^\(\.\+\\\.\)\?([A-Za-z0-9\\\.\-]+)\$$', p)
    if m:
        base = m.group(1).replace('\\.', '.')
        out.append(f"DOMAIN,{base}")
        if USE_WILDCARD:
            out.append(f"DOMAIN-WILDCARD,*.{base}")
        return out
    m2 = re.fullmatch(r'^\^([A-Za-z0-9\\\.\-]+)\$$', p)
    if m2:
        base = m2.group(1).replace('\\.', '.')
        out.append(f"DOMAIN,{base}")
        return out
    host = p[1:] if p.startswith('^') else p
    host = host[:-1] if host.endswith('$') else host
    out.append(f"URL-REGEX,^https?://{host}(?::\\d+)?(?:/|$)")
    return out

def to_surge_lines(rule: Rule):
    if rule.kind == "comment":
        return [f"# {rule.value}"] if ALLOW_COMMENTS else []
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
    dropped = 0
    with filepath.open("w", encoding="utf-8") as w:
        for r in rules:
            for line in to_surge_lines(r):
                line = line.strip()
                if not line:
                    continue
                if valid_line(line):
                    w.write(line + "\n")
                else:
                    dropped += 1
    return dropped

def build_all():
    files = sorted(p.name for p in DATA_DIR.iterdir() if p.is_file())
    total = 0
    total_dropped = 0
    for name in files:
        rules = resolve_list(name)
        dropped = write_ruleset(OUT_DIR / f"{name}.list", rules)
        total_dropped += dropped
        for attr in sorted(collect_attributes(rules)):
            filtered = [r for r in rules if isinstance(r, Rule) and (attr in r.attrs)]
            if filtered:
                total_dropped += write_ruleset(OUT_DIR / f"{name}@{attr}.list", filtered)
        total += 1
    print(f"Generated {total} Surge rulesets into {OUT_DIR}/, dropped {total_dropped} invalid lines")

if __name__ == "__main__":
    build_all()
