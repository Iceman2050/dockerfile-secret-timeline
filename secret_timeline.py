#!/usr/bin/env python3
"""
dockerfile-secret-timeline
==========================
Find out WHICH Dockerfile layer introduced each secret.

Parses a Dockerfile (or a `docker history`-style JSON export) and analyzes every
instruction for secret-introducing patterns:

  * ENV with secret-like names or high-entropy values
  * COPY / ADD of secret-ish files (.env, *.pem, id_rsa, ...)
  * ARG with default values (baked into image history/metadata)
  * RUN with inline credentials (curl -u user:pass, git clone https://user:token@, ...)

Pure static analysis -- no Docker daemon required.

Usage:
    python secret_timeline.py examples/vulnerable.Dockerfile
    python secret_timeline.py path/to/Dockerfile --json
    python secret_timeline.py --history history.json

`docker history` export format accepted by --history:
    [{"created_by": "RUN pip install -r requirements.txt", "size": 1234}, ...]
"""

import argparse
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Variable names that smell like secrets (case-insensitive).
SECRET_NAME_RE = re.compile(
    r"(secret|passwd|password|pwd|token|private[_-]?key|api[_-]?key|"
    r"access[_-]?key|auth[_-]?key|client[_-]?secret|credentials?|"
    r"session[_-]?key|signing[_-]?key)",
    re.IGNORECASE,
)

# Well-known token formats (values only).
KNOWN_FORMATS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("aws_secret_key", re.compile(r"\b[A-Za-z0-9/+=]{40}\b")),
    ("private_key_pem", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("jwt_like", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
]

# Source paths that should (almost) never be baked into an image.
SECRET_FILE_RE = re.compile(
    r"(^|/|\\)(\.env(\.|$)|.*\.pem$|.*\.key$|id_rsa.*|id_dsa.*|"
    r".*\.p12$|.*\.pfx$|secrets?(\.|$|_|-)|\.npmrc$|\.pypirc$|"
    r"credentials?(\.|$|_|-)|\.?aws/credentials|service[-_]account.*\.json$|"
    r".*\.jks$|\.git-credentials$)",
    re.IGNORECASE,
)

# Inline credentials inside RUN shell snippets.
RUN_CRED_RES = [
    ("basic_auth_flag", re.compile(r"(?:curl|wget)[^\n]*?(?:-u\s+|--user[=\s]+|--password[=\s]+|--ftp-password[=\s]+)\S+", re.IGNORECASE)),
    ("url_embedded_creds", re.compile(r"\bhttps?://[^/\s:]+:[^/\s@]+@[^\s'\"`]+", re.IGNORECASE)),
    ("export_secret", re.compile(r"\bexport\s+[A-Za-z_][A-Za-z0-9_]*\s*=\s*['\"]?[^\s'\";]+", re.IGNORECASE)),
    ("inline_secret_assignment", re.compile(r"\b[A-Za-z_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API[_-]?KEY)[A-Za-z_]*\s*=\s*['\"]?[^\s'\";]+", re.IGNORECASE)),
    ("docker_login_password", re.compile(r"docker\s+login[^\n]*?-p\s*\S+", re.IGNORECASE)),
    ("mysql_password", re.compile(r"mysql[^\n]*?-p\S+", re.IGNORECASE)),
    ("echo_secret_to_file", re.compile(r"echo\s+['\"]?[^'\"\n]*(?:password|secret|token|key)[^'\"\n]*['\"]?\s*>>?", re.IGNORECASE)),
]

ENTROPY_THRESHOLD = 4.0   # bits per char
ENTROPY_MIN_LEN = 16


def shannon_entropy(s):
    """Shannon entropy in bits per character."""
    if not s:
        return 0.0
    from math import log2
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * log2(c / n) for c in freq.values())


def looks_high_entropy(value):
    v = value.strip().strip("\"'")
    return len(v) >= ENTROPY_MIN_LEN and shannon_entropy(v) >= ENTROPY_THRESHOLD


# ---------------------------------------------------------------------------
# Dockerfile parsing
# ---------------------------------------------------------------------------

class Instruction:
    __slots__ = ("index", "keyword", "args", "raw")

    def __init__(self, index, keyword, args, raw):
        self.index = index        # 1-based position in the Dockerfile
        self.keyword = keyword    # upper-cased instruction keyword
        self.args = args          # remainder of the instruction
        self.raw = raw            # reconstructed single-line source

    def __repr__(self):
        return "Instruction(%d, %s, %r)" % (self.index, self.keyword, self.args)


def parse_dockerfile(path):
    """Parse a Dockerfile into a list of Instructions.

    Handles comments, blank lines, and backslash line continuations.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        physical = fh.readlines()

    # Join continued lines.
    logical = []
    buf = ""
    for line in physical:
        stripped = line.rstrip("\n")
        if stripped.rstrip().endswith("\\"):
            buf += stripped.rstrip()[:-1] + " "
        else:
            buf += stripped
            logical.append(buf)
            buf = ""
    if buf.strip():
        logical.append(buf)

    instructions = []
    idx = 0
    for line in logical:
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        idx += 1
        parts = s.split(None, 1)
        keyword = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""
        instructions.append(Instruction(idx, keyword, args, s))
    return instructions


def parse_history_json(path):
    """Parse a `docker history`-style JSON export into Instructions.

    History is newest-first; we reverse it so layer 1 is the base image and the
    timeline reads in build order.
    """
    with open(path, "r", encoding="utf-8") as fh:
        entries = json.load(fh)

    instructions = []
    idx = 0
    for entry in reversed(entries):
        created_by = (entry.get("created_by") or "").strip()
        if not created_by or created_by in ("", "<missing>"):
            continue
        # History lines look like "/bin/sh -c #(nop)  COPY file:abc ./" or
        # "/bin/sh -c apt-get update". Strip the shell prefix and nop marker.
        # A bare "/bin/sh -c <cmd>" entry is a RUN layer in disguise.
        m = re.match(r"^/bin/sh -c\s+#\(nop\)\s+(.*)$", created_by, re.IGNORECASE)
        if m:
            body = m.group(1).strip()
        else:
            m2 = re.match(r"^/bin/sh -c\s+(.*)$", created_by, re.IGNORECASE)
            body = ("RUN " + m2.group(1).strip()) if m2 else created_by.strip()
        if not body:
            continue
        idx += 1
        parts = body.split(None, 1)
        keyword = parts[0].upper()
        args = parts[1] if len(parts) > 1 else ""
        instructions.append(Instruction(idx, keyword, args, body))
    return instructions


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

class Finding:
    __slots__ = ("kind", "detail")

    def __init__(self, kind, detail):
        self.kind = kind      # e.g. "SECRET ENV VAR"
        self.detail = detail  # human-readable, value always redacted

    def __repr__(self):
        return "Finding(%r, %r)" % (self.kind, self.detail)


def _split_env_args(args):
    """Split ENV args into (name, value) pairs.

    Supports both `ENV KEY=val KEY2=val2` and legacy `ENV KEY val` forms.
    """
    pairs = []
    tokens = re.findall(r'''(?:[^\s"']+|"[^"]*"|'[^']*')+''', args)
    if not tokens:
        return pairs
    if "=" not in tokens[0] and len(tokens) >= 2 and "=" not in "".join(tokens[1:2]):
        # Legacy form: ENV KEY value (rest of line is the value)
        pairs.append((tokens[0], " ".join(tokens[1:])))
        return pairs
    for tok in tokens:
        if "=" in tok:
            name, _, value = tok.partition("=")
            pairs.append((name.strip(), value.strip()))
    return pairs


def analyze_env(args):
    findings = []
    for name, value in _split_env_args(args):
        v = value.strip().strip("\"'")
        reasons = []
        if SECRET_NAME_RE.search(name):
            reasons.append("secret-like name")
        for label, rx in KNOWN_FORMATS:
            if rx.search(v):
                reasons.append("matches %s format" % label)
                break
        else:
            if looks_high_entropy(v):
                reasons.append("high-entropy value")
        if reasons:
            findings.append(Finding(
                "SECRET ENV VAR",
                "%s=<redacted> (%s)" % (name, "; ".join(reasons)),
            ))
    return findings


def analyze_copy_add(keyword, args):
    findings = []
    # COPY/ADD args: [flags] <src>... <dest>. Last token is the dest.
    tokens = re.findall(r'''(?:[^\s"']+|"[^"]*"|'[^']*')+''', args)
    srcs = [t for t in tokens if not t.startswith("--")]
    if len(srcs) >= 2:
        srcs = srcs[:-1]  # drop destination
    elif len(srcs) == 1:
        srcs = []  # only a dest; nothing to check
    for src in srcs:
        s = src.strip("\"'")
        if SECRET_FILE_RE.search(s):
            findings.append(Finding(
                "SECRET FILE %s" % ("COPIED" if keyword == "COPY" else "ADDED"),
                "%s baked into image (matched secret-file pattern)" % s,
            ))
        elif s in (".", "./", "./.", ".."):
            findings.append(Finding(
                "BROAD CONTEXT COPY",
                "copies whole build context -- any .env / key files present get baked in",
            ))
    return findings


def analyze_arg(args):
    findings = []
    tokens = re.findall(r'''(?:[^\s"']+|"[^"]*"|'[^']*')+''', args)
    for tok in tokens:
        name, eq, default = tok.partition("=")
        if SECRET_NAME_RE.search(name) and eq:
            findings.append(Finding(
                "SECRET ARG DEFAULT",
                "%s has a default value -- ARG values persist in image history/metadata" % name,
            ))
        elif SECRET_NAME_RE.search(name):
            findings.append(Finding(
                "SECRET-LIKE ARG",
                "%s looks secret-like; if passed at build time it persists in image history" % name,
            ))
    return findings


def analyze_run(args):
    findings = []
    for label, rx in RUN_CRED_RES:
        for m in rx.finditer(args):
            snippet = m.group(0)
            if len(snippet) > 80:
                snippet = snippet[:77] + "..."
            findings.append(Finding(
                "INLINE CREDENTIALS",
                "%s: %s" % (label.replace("_", " "), snippet),
            ))
    # Dedupe identical findings.
    seen = set()
    uniq = []
    for f in findings:
        key = (f.kind, f.detail)
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def analyze_instruction(instr):
    kw = instr.keyword
    if kw == "ENV":
        return analyze_env(instr.args)
    if kw in ("COPY", "ADD"):
        return analyze_copy_add(kw, instr.args)
    if kw == "ARG":
        return analyze_arg(instr.args)
    if kw == "RUN":
        return analyze_run(instr.args)
    return []


def build_timeline(instructions):
    """Return [(instruction, [findings])] for the whole Dockerfile/history."""
    return [(instr, analyze_instruction(instr)) for instr in instructions]


# ---------------------------------------------------------------------------
# Display redaction
# ---------------------------------------------------------------------------

def redact_instruction(instr, findings):
    """Return a display-safe rendering of an instruction.

    A secret scanner must never echo raw secret values -- not even the user's
    own -- so value-bearing instructions with findings are shown with their
    values masked. Instructions without findings are shown verbatim.
    """
    if not findings:
        return instr.raw
    orig_kw = instr.raw.split(None, 1)[0] if instr.raw.split(None, 1) else instr.keyword
    kw, args = instr.keyword, instr.args
    if kw == "ENV":
        parts = []
        for name, value in _split_env_args(args):
            if analyze_env("%s=%s" % (name, value)):
                parts.append("%s=<redacted>" % name)
            else:
                parts.append("%s=%s" % (name, value))
        return orig_kw + " " + " ".join(parts)
    if kw == "ARG":
        def mask_arg(m):
            name = m.group(1)
            if analyze_arg(name + "=x"):
                return name + "=<redacted>"
            return m.group(0)
        return orig_kw + " " + re.sub(r"([A-Za-z_][A-Za-z0-9_]*)=(\S+)", mask_arg, args)
    if kw == "RUN":
        red = args
        for _label, rx in RUN_CRED_RES:
            red = rx.sub("[credential redacted]", red)
        return orig_kw + " " + red
    return instr.raw


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_text(timeline, source_label):
    # Findings always print on their own continuation lines, never on the same
    # line as the raw instruction: a value-bearing instruction line may be
    # redacted by output filters, and the finding must survive that.
    total_layers = len(timeline)
    total_findings = sum(len(f) for _, f in timeline)
    lines = []
    lines.append("Secret timeline for: %s" % source_label)
    lines.append("=" * 72)
    lines.append("%-6s %s" % ("Layer", "Instruction"))
    lines.append("-" * 72)
    for instr, findings in timeline:
        shown = redact_instruction(instr, findings)
        short = shown if len(shown) <= 60 else shown[:58] + ".."
        lines.append("%-6d %s" % (instr.index, short))
        for f in findings:
            lines.append("       -> [%s] %s" % (f.kind, f.detail))
    lines.append("-" * 72)
    lines.append("Result: %d finding(s) across %d layer(s)." % (total_findings, total_layers))
    if total_findings:
        lines.append("Every value above is redacted -- fix the Dockerfile, not the report.")
    else:
        lines.append("No secret-introducing patterns detected.")
    return "\n".join(lines) + "\n"


def render_json(timeline, source_label):
    layers = []
    for instr, findings in timeline:
        layers.append({
            "layer": instr.index,
            "instruction": instr.keyword,
            "source": redact_instruction(instr, findings),
            "findings": [{"kind": f.kind, "detail": f.detail} for f in findings],
        })
    return json.dumps({
        "source": source_label,
        "layers": layers,
        "total_layers": len(layers),
        "total_findings": sum(len(f) for _, f in timeline),
    }, indent=2) + "\n"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Show which Dockerfile layer introduced each secret (no Docker daemon needed)."
    )
    ap.add_argument("dockerfile", nargs="?",
                    help="Path to the Dockerfile to analyze.")
    ap.add_argument("--history",
                    help="Analyze a docker-history-style JSON export instead of a Dockerfile.")
    ap.add_argument("--json", action="store_true",
                    help="Emit machine-readable JSON.")
    args = ap.parse_args(argv)

    if args.history:
        if not os.path.isfile(args.history):
            print("error: history file not found: %s" % args.history, file=sys.stderr)
            return 2
        instructions = parse_history_json(args.history)
        source_label = args.history + " (history, reversed into build order)"
    elif args.dockerfile:
        if not os.path.isfile(args.dockerfile):
            print("error: Dockerfile not found: %s" % args.dockerfile, file=sys.stderr)
            return 2
        instructions = parse_dockerfile(args.dockerfile)
        source_label = args.dockerfile
    else:
        ap.print_usage(sys.stderr)
        print("error: provide a Dockerfile path or --history FILE", file=sys.stderr)
        return 2

    if not instructions:
        print("error: no instructions found to analyze", file=sys.stderr)
        return 2

    timeline = build_timeline(instructions)
    out = render_json(timeline, source_label) if args.json else render_text(timeline, source_label)
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
