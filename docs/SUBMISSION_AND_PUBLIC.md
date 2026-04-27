# Submitting to CoSAI/OASIS + Making Repos Public

## Status checklist before going public

Both repos are clean for public visibility:
- No credential values in source or git history
- No internal hostnames, tokens, or database schema details in tracked files
- Internal session context docs are gitignored
- Apache 2.0 license in place

---

## Making the repos public

### cosai-mcp (the scanner)

```bash
gh repo edit ragsvasan/cosai-mcp --visibility public
```

Or via GitHub web: Settings → General → Danger Zone → Change repository visibility → Public.

**Before flipping:**
1. Read through the README to confirm it doesn't reference internal services
2. Check `docs/workplan.md` — the Mnemo section is fine (generic auth-server example); the internal DB details were removed
3. The `docs/P10-P12-CONTEXT.md` is already gitignored and removed from tracking

### mcp-armor (the SDK)

```bash
gh repo edit ragsvasan/mcp-armor --visibility public
```

Both can go public simultaneously — they reference each other by repo name only, not by URL.

### After going public

Update cross-references in both READMEs from relative paths to full GitHub URLs:
- cosai-mcp README: add link to mcp-armor as the companion server-side SDK
- mcp-armor README: add link to cosai-mcp as the companion scanner

---

## Submitting to CoSAI / OASIS

### What CoSAI is

CoSAI (Coalition for Secure AI) is an OASIS Open project. The January 2026 whitepaper
"Security Taxonomy and Governance Framework for the Model Context Protocol" (T1–T12) is the
spec this tool implements. Submitting positions cosai-mcp as the reference runtime implementation
of that spec — the same relationship pytest has to PEP 8 or OpenSSL has to RFC 5246.

### Submission path

There are two distinct tracks:

#### Track 1 — CoSAI MCP Working Group (fastest, most direct)

The MCP security working group within CoSAI is the right home for a runtime scanner.
Contact and next steps:

1. **Find the working group:** go to https://www.oasis-open.org/committees/cosai/ and look
   for the MCP Security subcommittee or Technical Committee. As of early 2026 this is the
   active group that produced the T1–T12 taxonomy.

2. **Join as a contributor:** OASIS membership is free for individuals contributing to open
   standards. Go to https://www.oasis-open.org/join/ → Individual membership. This gives you
   mailing list access and the right to contribute.

3. **Post to the mailing list:** introduce cosai-mcp as a reference implementation of their
   taxonomy. Subject line: "Reference runtime scanner for MCP T1–T12 taxonomy — open source,
   Apache 2.0". Include:
   - What it does (black-box JSON-RPC prober + stateful conformance harness + all 12 categories)
   - A link to the public GitHub repo
   - The SARIF output (GitHub-native security tab integration)
   - The CI/CD GitHub Action (one-line adoption)
   - That you're looking for feedback and potential co-authorship of future catalog entries

4. **Propose a contribution:** once in the working group, propose cosai-mcp as an official
   companion tool to the taxonomy paper. The deliverable would be a "runtime compliance test
   suite" document that references this repo, similar to how OWASP references tools in its
   Top 10.

#### Track 2 — OWASP MCP Top 10 (parallel, broader reach)

The OWASP MCP Top 10 project (separate from CoSAI but aligned) is actively recruiting tools.
cosai-mcp maps directly to their A01–A10 categories.

1. Go to the OWASP MCP Top 10 GitHub org and open an issue or PR with the tool submission
2. The OWASP project page will link to cosai-mcp as a testing tool for each Top 10 category
3. This is faster than OASIS and reaches a larger developer audience

### What to prepare before submitting

**A clean README.md with:**
- 30-second install + scan (zero-config path)
- Coverage matrix (T1–T12, three engines, what each covers)
- SARIF output screenshot / GitHub security tab screenshot
- "Compare to" section positioning against static scanners (they're complements, not competitors)
- Apache 2.0 badge, CI badge, PyPI badge (add once published)

**A one-page position paper** (can be a GitHub wiki page or `docs/POSITION.md`):
- The gap: "Every existing tool is either static analysis, a proxy, or a commercial service.
  None provide runtime black-box conformance testing against the full CoSAI taxonomy."
- The design: three-engine architecture (prober, stateful harness, middleware)
- The contract: SARIF output, fail-closed exit codes, CI-native

**A live demo target** (for the working group presentation):
- A minimal FastMCP server with known vulnerabilities
- A recorded cosai-mcp scan showing findings + remediation tab
- The adversarial probe demo once P13 is complete

### Positioning to the working group

Lead with the gap, not the tool. The pitch is:

> "The T1–T12 taxonomy is the right framework. What's missing is a runtime conformance test
> that server authors can run in CI before shipping. cosai-mcp fills that gap the same way
> pytest fills the gap for unit testing — you write the spec, we verify the running server
> matches it. We'd like to contribute the catalog format and test harness as a standard
> alongside the taxonomy paper."

This frames it as completing their work, not competing with it.

### Timeline

| Step | When |
|------|------|
| Make repos public | Now (repos are clean) |
| Publish to PyPI (needs P7 complete) | After P7 |
| Post to CoSAI mailing list | After PyPI — have a real install story |
| Propose to OWASP MCP Top 10 | Same time as CoSAI post |
| Present to working group | After P12 (remediation-first report makes the demo compelling) |
| Propose P13 adversarial probes as standard catalog contribution | After P13 |
