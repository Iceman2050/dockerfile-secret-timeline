# dockerfile-secret-timeline

**Your image leaked an AWS key. Was it the `ENV` on line 9, the `.env` you `COPY`d on line 6, or the `curl -u deploy:...` buried in a `RUN`?** `docker history` won't tell you — it just shows hashes. This tool tells you exactly which layer introduced each secret, before you push the image.

No Docker daemon needed. Pure static analysis of the Dockerfile (or a `docker history` JSON export) in under a second.

## Quickstart (30 seconds)

```bash
git clone https://github.com/Iceman2050/dockerfile-secret-timeline.git
cd dockerfile-secret-timeline
python3 secret_timeline.py examples/vulnerable.Dockerfile
```

A deliberately leaky `examples/vulnerable.Dockerfile` is included so you can see all five finding types immediately. Also try the clean one:

```bash
python3 secret_timeline.py examples/clean.Dockerfile
```

Analyze an existing image's history instead (export it with `docker history --format '{{json .}}'` massaged into a JSON array, or any list of `{"created_by": ...}` objects):

```bash
python3 secret_timeline.py --history history.json
python3 secret_timeline.py examples/vulnerable.Dockerfile --json   # machine-readable
```

## Example output

Real output from `python3 secret_timeline.py examples/vulnerable.Dockerfile` (values redacted by the tool itself):

```
Secret timeline for: examples/vulnerable.Dockerfile
========================================================================
Layer  Instruction
------------------------------------------------------------------------
1      FROM python:3.12-slim
2      WORKDIR /app
3      ARG BUILD_TOKEN=<redacted>
       -> [SECRET ARG DEFAULT] BUILD_TOKEN has a default value -- ARG values persist in image history/metadata
4      COPY requirements.txt .
5      RUN pip install --no-cache-dir -r requirements.txt
6      COPY .env /app/.env
       -> [SECRET FILE COPIED] .env baked into image (matched secret-file pattern)
7      ENV AWS_SECRET_ACCESS_KEY=<redacted>
       -> [SECRET ENV VAR] AWS_SECRET_ACCESS_KEY=<redacted> (secret-like name)
8      ENV APP_ENV=production
9      RUN [credential redacted] https://artifacts.internal.examp..
       -> [INLINE CREDENTIALS] basic auth flag: curl -u deploy:DEMO_PASSWORD
10     COPY . .
       -> [BROAD CONTEXT COPY] copies whole build context -- any .env / key files present get baked in
11     EXPOSE 8000
12     CMD ["python", "app.py"]
------------------------------------------------------------------------
Result: 5 finding(s) across 12 layer(s).
Every value above is redacted -- fix the Dockerfile, not the report.
```

## What it finds

| Pattern | Example | Why it matters |
|---|---|---|
| `ENV` with secret-like name/value | `ENV AWS_SECRET_ACCESS_KEY=...` | Baked into the image config, visible to anyone who pulls it |
| `COPY`/`ADD` of secret files | `COPY .env /app/`, `*.pem`, `id_rsa` | File lands in a layer forever, even if a later layer deletes it |
| `ARG` with default value | `ARG BUILD_TOKEN=...` | Persists in image history/metadata |
| Inline credentials in `RUN` | `curl -u user:pass`, `git clone https://user:token@...` | Visible in `docker history` output for the layer |
| Broad context copy | `COPY . .` | Silently includes any `.env`/key files in the build context |

Detection combines secret-like variable names, well-known token formats (AWS, GitHub, Slack, OpenAI, Stripe, JWT, PEM), Shannon-entropy checks on values, and secret-file path patterns. Every reported value is shown as `<redacted>` — the report never leaks the secret further.

## What it does NOT do

- **It does not scan image contents or running containers.** It analyzes Dockerfiles and history metadata only; use a secret scanner (e.g. Gitleaks, TruffleHog) for content already baked into layers.
- **It cannot prove a value is a real secret.** High-entropy strings and secret-like names are heuristics — expect false positives on things like `SESSION_KEY=abc123xyz...` placeholders. Tune by renaming non-secret vars.
- **It does not see secrets injected at runtime** (mounted files, orchestrator secret stores, `--secret` mounts) — those are the *right* way to do it and correctly produce zero findings.
- **History mode trusts your export.** Reordered or truncated `docker history` JSON gives a misleading timeline; the tool reverses newest-first history into build order and says so.

## Development

```bash
python3 -m unittest discover -s tests -v   # 25 tests, stdlib only
```

## License

MIT — see [LICENSE](LICENSE).

## Built by Ingenious AI
- DisclosureGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DisclosureGuard.
- ModelMinder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ModelMinder.
- TermsWatch — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20TermsWatch.
- Vibe-Code Audit — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Vibe-Code%20Audit.
- Rogue-Agent Defense — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense.
- BreachHunter — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20BreachHunter.
- ChatBreaker — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ChatBreaker.
- Agent Flight Recorder — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder.
- Agent Auth Gateway — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway.
- DomainGuard — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20DomainGuard.
- ContentCraft AI — https://wa.me/5016691053?text=Hi%20Ingenious%20AI%21%20I%20want%20early%20access%20to%20ContentCraft%20AI.
