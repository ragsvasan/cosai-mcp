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

### Q: What if the ecosystem moves to different cryptography?

If Ed25519 is deprecated, we can:
1. Support multiple algorithms via a `signature_algorithm` field in the JSON
2. Issue a new binary with a new key and upgraded validation logic
3. Publish an attestation explaining the transition

This is a low-probability event — Ed25519 is a modern standard with no known cryptographic weaknesses and is standardized in FIPS and NIST guidelines.

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
