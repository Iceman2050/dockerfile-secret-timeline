#!/usr/bin/env python3
"""Tests for secret_timeline.py.

Security note: no literal secret-looking strings appear in this file. Every
fake credential used as a test input is built by string concatenation so it
can never be mistaken for a real leaked secret.
"""

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import secret_timeline as st


def fake_high_entropy():
    # 48 chars, 24 unique symbols -> ~4.58 bits/char, clearly synthetic.
    return ("abcdefgh" + "ABCDEFGH" + "01234567") * 2


def fake_github_token():
    return "ghp_" + "a1B2" * 9


def fake_aws_key_id():
    return "AK" + "IA" + "X" * 16


def write_tmp(content, suffix=".Dockerfile"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as fh:
        fh.write(content)
    return path


class TestParsing(unittest.TestCase):
    def test_continuation_lines_joined(self):
        p = write_tmp("FROM x\nRUN echo a \\\n    && echo b\n")
        try:
            instrs = st.parse_dockerfile(p)
            self.assertEqual(len(instrs), 2)
            self.assertIn("echo b", instrs[1].args)
        finally:
            os.unlink(p)

    def test_comments_and_blanks_skipped_but_numbering_sequential(self):
        p = write_tmp("# hi\n\nFROM x\n# yo\nRUN y\n")
        try:
            instrs = st.parse_dockerfile(p)
            self.assertEqual([i.index for i in instrs], [1, 2])
        finally:
            os.unlink(p)

    def test_keyword_case_insensitive(self):
        p = write_tmp("from x\nenv A=b\n")
        try:
            instrs = st.parse_dockerfile(p)
            self.assertEqual(instrs[0].keyword, "FROM")
            self.assertEqual(instrs[1].keyword, "ENV")
        finally:
            os.unlink(p)


class TestEnvAnalysis(unittest.TestCase):
    def test_secret_name_flagged(self):
        f = st.analyze_env("DB_PASSWORD=hunter2")
        self.assertEqual(len(f), 1)
        self.assertIn("DB_PASSWORD", f[0].detail)

    def test_clean_env_not_flagged(self):
        self.assertEqual(st.analyze_env("APP_ENV=production"), [])
        self.assertEqual(st.analyze_env("PORT=8000"), [])

    def test_high_entropy_value_flagged(self):
        f = st.analyze_env("MYSTERY=" + fake_high_entropy())
        self.assertEqual(len(f), 1)
        self.assertIn("high-entropy", f[0].detail)

    def test_known_format_flagged(self):
        f = st.analyze_env("TOKEN=" + fake_github_token())
        self.assertEqual(len(f), 1)
        self.assertIn("github_token", f[0].detail)

    def test_legacy_env_form(self):
        f = st.analyze_env("AWS_KEY " + fake_aws_key_id())
        self.assertEqual(len(f), 1)


class TestCopyAddAnalysis(unittest.TestCase):
    def test_copy_dotenv_flagged(self):
        f = st.analyze_copy_add("COPY", ".env /app/.env")
        self.assertTrue(any(".env" in x.detail for x in f))

    def test_copy_pem_flagged(self):
        f = st.analyze_copy_add("COPY", "certs/server.pem /etc/ssl/")
        self.assertTrue(f)

    def test_copy_benign_not_flagged(self):
        self.assertEqual(st.analyze_copy_add("COPY", "requirements.txt ."), [])

    def test_copy_whole_context_warns(self):
        f = st.analyze_copy_add("COPY", ". .")
        self.assertTrue(any("BROAD" in x.kind for x in f))

    def test_add_key_file_flagged(self):
        f = st.analyze_copy_add("ADD", "id_rsa /root/.ssh/")
        self.assertTrue(f)


class TestArgAnalysis(unittest.TestCase):
    def test_secret_arg_with_default_flagged(self):
        f = st.analyze_arg("BUILD_TOKEN=demo" + "-placeholder")
        self.assertTrue(any("DEFAULT" in x.kind for x in f))

    def test_secret_arg_without_default_warns(self):
        f = st.analyze_arg("DB_PASSWORD")
        self.assertTrue(any("SECRET-LIKE ARG" in x.kind for x in f))

    def test_benign_arg_not_flagged(self):
        self.assertEqual(st.analyze_arg("APP_VERSION=1.2.3"), [])


class TestRunAnalysis(unittest.TestCase):
    def test_curl_basic_auth_flagged(self):
        f = st.analyze_run("curl -u deploy:" + "s3cr3t-pw" + " https://x.example/y -o y")
        self.assertTrue(f)

    def test_url_embedded_creds_flagged(self):
        f = st.analyze_run("git clone https://oauth2:" + "tok123" + "@github.com/a/b.git")
        self.assertTrue(any("url embedded creds" in x.detail for x in f))

    def test_benign_run_not_flagged(self):
        self.assertEqual(st.analyze_run("apt-get update && apt-get install -y curl"), [])
        self.assertEqual(st.analyze_run("pip install -r requirements.txt"), [])


class TestTimeline(unittest.TestCase):
    def test_layer_numbering_and_findings(self):
        p = write_tmp("FROM x\nENV APP_ENV=prod\nCOPY .env /app/\n")
        try:
            tl = st.build_timeline(st.parse_dockerfile(p))
            self.assertEqual([i.index for i, _ in tl], [1, 2, 3])
            self.assertEqual(tl[2][1][0].kind, "SECRET FILE COPIED")
        finally:
            os.unlink(p)

    def test_values_redacted_in_text_output(self):
        secret = fake_github_token()
        p = write_tmp("FROM x\nENV TOKEN=" + secret + "\n")
        try:
            out = st.render_text(st.build_timeline(st.parse_dockerfile(p)), p)
            self.assertNotIn(secret, out)
            self.assertIn("<redacted>", out)
        finally:
            os.unlink(p)

    def test_json_output_structure(self):
        p = write_tmp("FROM x\nCOPY .env /app/\n")
        try:
            tl = st.build_timeline(st.parse_dockerfile(p))
            data = json.loads(st.render_json(tl, p))
            self.assertEqual(data["total_layers"], 2)
            self.assertEqual(data["total_findings"], 1)
            self.assertEqual(data["layers"][1]["findings"][0]["kind"], "SECRET FILE COPIED")
        finally:
            os.unlink(p)

    def test_clean_dockerfile_no_findings(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        clean = os.path.join(here, "examples", "clean.Dockerfile")
        tl = st.build_timeline(st.parse_dockerfile(clean))
        self.assertEqual(sum(len(f) for _, f in tl), 0)

    def test_history_json_mode(self):
        entries = [
            {"created_by": "/bin/sh -c #(nop) COPY file:abc123 .env /app/.env"},
            {"created_by": "/bin/sh -c #(nop)  ENV APP_ENV=production"},
            {"created_by": "/bin/sh -c apt-get update"},
        ]
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            json.dump(entries, fh)
        try:
            instrs = st.parse_history_json(path)
            # Reversed into build order: apt-get first, .env COPY last.
            self.assertEqual(instrs[0].keyword, "RUN")
            tl = st.build_timeline(instrs)
            total = sum(len(f) for _, f in tl)
            self.assertEqual(total, 1)
            self.assertEqual(tl[2][0].index, 3)
        finally:
            os.unlink(path)

    def test_cli_end_to_end_on_vulnerable_example(self):
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        vuln = os.path.join(here, "examples", "vulnerable.Dockerfile")
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = st.main([vuln])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Result:", out)
        # At least the .env COPY, the ENV, the ARG default and the RUN creds.
        self.assertGreaterEqual(out.count("["), 4)


if __name__ == "__main__":
    unittest.main()
