# Catalog Signing & Trust — FAQ

The official threat definitions are Ed25519-signed with a public key hardcoded into the scanner binary. This protects against catalog poisoning — even if an attacker compromises the PyPI package or modifies files on disk, the scanner will reject unsigned definitions.

---

## How does it work?

**What gets signed:**
- Official threat definition JSON files in `catalog/official/` (e.g., `T01-auth.json`, `T04-tool-poisoning.json`)
- Verified at catalog load time using Ed25519 signature validation
- If a file's signature doesn't match the hardcoded public key, the scanner refuses to load it

**The public key:**
```python
# cosai_mcp/keys.py
COSAI_PUBKEY = b'\x...'  # 32-byte Ed25519 public key, hardcoded as bytes literal
```

**Why hardcoded, not loaded from disk or environment:**

If the key were in a file or environment variable, a compromised install could swap it. Hardcoding solves this by making the key immutable and part of the binary itself — even if an attacker poisons the PyPI package, they cannot forge a valid signature without the private key.

---

## Common Questions

### Q: What if the hardcoded key is compromised?

If the binary itself is compromised, you need a new binary with a new key. The hardcoding prevents compromise *of the key independent from the binary* — it doesn't defend against a fully compromised build pipeline.

For key rotation in enterprise deployments:
```bash
COSAI_PUBKEY=<new_key_base64> cosai scan http://localhost:8000
```

The `COSAI_PUBKEY` environment variable overrides the hardcoded key. But it must be explicitly set — it defaults to the hardcoded key.

### Q: Can I use my own organization's signing key?

Yes. Create your own Ed25519 keypair, sign threat definitions with the private key, and instruct the scanner to use your public key:

```bash
COSAI_PUBKEY=<your_base64_key> cosai scan http://localhost:8000
```

This is useful if you want to:
- Maintain your own internal threat definitions
- Rotate keys on your own schedule
- Integrate with your organization's secrets management

You become responsible for secure key storage and distribution.

### Q: What about custom threats in `catalog/custom/`?

Custom threats are **not signed** — they are user-provided and assumed to be trusted by the operator. The `--allow-custom-catalog` flag (off by default) is required to load them.

This is intentional separation:
- Official threats (signed) ← project authority
- Custom threats (unsigned) ← user responsibility

### Q: Why isn't the key stored in an environment variable by default?

Environment variables can be poisoned by a compromised script or container. Hardcoding ensures the key is immutable at binary load time, not injected at runtime.

The environment variable override exists for enterprises that need key rotation, but they explicitly opt in — they control that security boundary themselves.

### Q: What if I have an old binary and you rotate the key?

The old binary will have the old key hardcoded. It won't validate threat definitions signed with the new key. You'll get an `UnsignedFileError` when the scanner tries to load the official catalog.

Solution: Update the binary. Key updates are tied to binary releases — there's no automatic background breakage.

### Q: How do I verify the public key is actually yours?

The public key is published in multiple places:
1. **GitHub release notes** — every release includes the key fingerprint
2. **Sigstore/PEP 740 attestation** — cryptographic proof the binary matches the source
3. **Source code** — inspect `cosai_mcp/keys.py` before installing to verify it matches the published key

```bash
# Before install: inspect the key in source
python3 -c "import ast; print(ast.literal_eval(open('cosai_mcp/keys.py').read().split('=')[1].strip()))"
```

### Q: Can I see the actual signature on a threat definition file?

The signature is checked internally at load time; it's not exposed in the output. If you want to inspect it manually, the JSON threat definitions can optionally include a `_signature` field (the spec is in `docs/CONTRIBUTING.md`).

```bash
# Inspect a threat definition
jq . catalog/official/T01-auth.json
```

### Q: What if I'm running the scanner in a compromised environment?

If your Python runtime is compromised (e.g., via `LD_PRELOAD` or a malicious .pyc file), signature checking is just one of many bypasses available to an attacker. Hardcoding the key prevents one specific attack — catalog poisoning at the package level — but doesn't defend against a fully compromised runtime.

If your environment might be compromised, threats include:
- Replacing the scanner binary itself
- Intercepting network traffic
- Modifying Python bytecode

Trust the environment first; signature checking is a defense-in-depth layer.

### Q: What's the threat model you're defending against?

**Attacker scenario 1: PyPI package poisoning**
- Attacker compromises the cosai-mcp package on PyPI
- Tries to inject malicious threat definitions into `catalog/official/`
- Scanner loads, checks signature, rejects them (doesn't match hardcoded key)
- Attack fails

**Attacker scenario 2: Filesystem tampering**
- You have the legitimate binary, but an attacker modifies `catalog/official/T04.json` on disk
- Same result: signature doesn't match, file is rejected

**Attacker scenario 3: Supply chain drift**
- You fetch the scanner from two different mirrors; one is poisoned
- The poisoned mirror includes malicious threat definitions
- The hardcoded key ensures only the real definitions load

### Q: How is the signature format validated?

Ed25519 signatures are validated using `joserfc` (or `PyJWT[crypto]` as fallback) at catalog load time. Invalid signatures cause `UnsignedFileError`. The threat catalog JSON schema is validated before signature checking, so schema violations fail fast and independently of signature verification.

### Q: Can't an attacker modify the binary to include their own hardcoded key?

Yes, they *can* modify the binary. But that's a different attack — binary modification, not catalog poisoning — and it's detectable.

**The distinction:**

The hardcoded key defends against **catalog poisoning without modifying the binary** — the narrow case where an attacker compromises PyPI but cannot forge signatures.

If an attacker goes further and modifies the binary to include their own key, they've now changed the binary itself. This is detectable via:

1. **Sigstore attestation** — the binary is cryptographically signed by the project. A modified binary fails verification.
   ```bash
   cosign verify ghcr.io/ragsvasan/cosai-mcp:v1.2.3 \
     --certificate-identity-regexp "cosai-mcp" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com"
   ```

2. **Hash verification** — the binary's SHA-256 is published on releases. An attacker-modified binary has a different hash.
   ```bash
   sha256sum cosai-mcp-v1.2.3.tar.gz
   # Must match the published hash on GitHub releases
   ```

3. **Source inspection** — before installing, inspect `cosai_mcp/keys.py` in the source.
   ```bash
   git show v1.2.3:cosai_mcp/keys.py | grep COSAI_PUBKEY
   ```

4. **Supply chain tooling** — SBOMs, transparency logs, and CI attestations make silent binary modifications detectable.

**Threat model layers:**

| Layer | Attack | Defense |
|-------|--------|---------|
| Catalog only | Poison `/catalog/official/` without private key | Hardcoded public key |
| Binary + catalog | Modify binary with attacker's key | Sigstore attestation + hash verification |
| Binary + supply chain | Slip a modified binary past all checks | Transparency logs + offline verification |

The hardcoded key wins at layer 1. Layers 2+ require Sigstore and hash verification, which are published with every release.

### Q: If enterprises get the `COSAI_PUBKEY` env var, can't attackers use it too?

Yes, they *could* set the env var. But that assumes they've already compromised your infrastructure — at which point the env var is irrelevant.

**The key distinction:** `COSAI_PUBKEY` is NOT a security feature — it's an operational convenience for key rotation.

**Who controls the environment?**

In an enterprise deployment:
- Environment variables are set by secrets management (AWS Secrets Manager, Vault, etc.)
- Only IAM-authenticated operators can modify them
- The enterprise explicitly decides to rotate keys and how to distribute them

An attacker could set `COSAI_PUBKEY` if they:
- Compromised the CI/CD pipeline (attacker already has root)
- Compromised the container build (attacker already has root)
- Compromised the deployment server (attacker already has root)
- Have SSH/shell access (attacker already has root)

All of these are "attacker owns your infrastructure" scenarios. At that point, the attacker can:
- Replace the entire scanner binary
- Modify threat definitions on disk
- Intercept scan results
- Disable scanning entirely

The env var is moot in a compromised environment.

**Threat models are different:**

| Scenario | Defense |
|----------|---------|
| PyPI is compromised, but my build is clean | Hardcoded key (attacker can't forge without private key) |
| I trust my environment but want to rotate keys | Env var (enterprise operational convenience) |
| My infrastructure is compromised | No defense; you're already breached |

The hardcoded key is the security boundary (stops PyPI poisoning). The env var is a convenience boundary (enables key rotation in a *trusted* environment). Don't confuse them.

### Q: If env var access implies the infrastructure is compromised, why bother hardcoding at all?

Because they defend **different threat models** at different supply-chain layers.

**Hardcoding defends against: PyPI poisoning (supply chain, no infrastructure compromise required)**
- Developer runs `pip install cosai-mcp` 
- Attacker poisons the release on PyPI with malicious threat definitions
- Developer's local machine, CI/CD runner, or clean container pulls the poisoned version
- Hardcoded key in the binary rejects the unsigned catalog entries — attack fails
- This is real and has happened (SolarWinds, Codecov, xz-utils)

**Env var is for: Enterprise key rotation (operational convenience, assumes trusted environment)**
- Enterprise controls their CI/CD, secrets manager, deployment servers
- They want to rotate signing keys without shipping a new binary
- They set `COSAI_PUBKEY` from their secrets manager
- This assumes the environment is already trusted — if someone can modify env vars, they've already compromised infrastructure. But that doesn't invalidate hardcoding; it means env var is not a security feature, just an operational one.

**Threat models are different:**

| Layer | Attacker Power | Defense |
|-------|---|---|
| PyPI package | Compromises release, no private key | Hardcoded key in binary ✓ |
| Developer machine | Installs poisoned release, can set env vars | Hardcoding wins; env var is moot |
| Enterprise CI/CD | Controls secrets and env vars | Env var enables key rotation (not a security boundary, an operational feature) |
| Infrastructure root | Can replace binary, modify env, disable scanning | Game over; neither helps |

**The bottom line:** Hardcoding solves a narrow but real problem (PyPI supply-chain poisoning). The env var doesn't weaken hardcoding — they address different use cases. Hardcoding is supply-chain defense. Env var is operational flexibility. Don't confuse them.

### Q: Who controls the private key?

Currently: the project maintainers.

Proposal to CoSAI/OASIS: transfer signing authority to the WS4 working group, similar to how the OWASP Top 10 governance works. Community submits threats, working group ratifies, signed artifacts ship.

---

## For Developers

**Adding a new threat definition:**
1. Create `catalog/official/T##-description.json`
2. Sign it with the project private key (stored securely, not in the repo)
3. Publish both the definition and its signature
4. CI validates the signature before merging

**Submitting a threat to the official catalog:**
- Open an issue in the CoSAI working group repository
- Describe the threat, attack patterns, and remediation
- Once ratified, the working group signs and publishes it

**Custom threats:**
```bash
cosai scan http://localhost:8000 --allow-custom-catalog
```
- Place your threat definitions in `catalog/custom/`
- No signature required
- User responsibility for vetting

---

## References

- **Threat Catalog Format:** [docs/CONTRIBUTING.md](CONTRIBUTING.md#threat-definition-schema)
- **Security Model:** [docs/SECURITY.md](SECURITY.md)
- **Architecture Decisions:** [docs/architecture-decisions.md](architecture-decisions.md)
