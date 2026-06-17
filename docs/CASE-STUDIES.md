# Herkos case studies

These are worked examples built on **real, documented 2025 MCP incidents**, not invented
scenarios. The point is to test the product honestly: for each incident, what would Herkos
actually have done? The answer is consistent and it is the reason for the product's
direction:

> **Herkos is weak at prevention and strong at provable audit.** The headline MCP attacks
> defeat tool-name allowlisting (they ride tools the user already approved, or leak
> server-side where an in-path broker cannot see). What Herkos uniquely gives you is a
> signed, offline-verifiable record of what the agent did and what code touched the model.
> So the anchor is the receipt, not the broker.

Each case lists the source, what happened, what Herkos's **broker** (deny-by-default
tool-name allowlist) would do, and what Herkos's **receipt** (signed provenance) would do.

---

## 1. GitHub MCP "toxic agent flow" - exfil through an approved tool

**Source:** Invariant Labs, May 26 2025 (`invariantlabs.ai/blog/mcp-github-vulnerability`).
Official GitHub MCP server, 14k+ stars at disclosure. No CVE (framed as architectural); a
community member later filed reproduction issue `github/github-mcp-server#844`.

**What happened:** A malicious public-repo *issue* contains injected instructions. The
user's agent, which also has access to their private repos, follows them and leaks private
data (repo names, salary, address per the PoC) by opening an **auto-created public pull
request**. Invariant notes this is architectural, not a server bug to patch.

- **Broker verdict - does NOT prevent.** `create_pull_request` is a tool the user
  legitimately allowed. A tool-name allowlist passes it. Prevention here needs
  content/provenance egress, which is the hard layer Herkos has not built.
- **Receipt verdict - strong.** The receipt records that `create_pull_request` ran and
  which source spans were in context, signed and timestamped. After the leak you can prove
  exactly what left and when. This is the realistic value: forensics, not a force field.

**Honest overall:** prevention aspirational; audit real.

---

## 2. postmark-mcp - malicious server, server-side BCC exfil

**Source:** Koi Security, Sep 25 2025; Snyk same day (`koi.ai/blog/postmark-mcp-npm-malicious-backdoor-email-theft`).
Widely documented as the first real-world malicious MCP server; versions 1.0.16-1.0.18 silently
BCC'd every email to `phan@giftshop[.]club`; ~1,643 downloads over an ~8-day window (Koi put
active orgs in the low hundreds, an explicit estimate).

- **Broker verdict - does NOT prevent.** `send_email` is the allowed, intended tool. The
  malicious BCC is added **server-side**, on the server's own outbound SMTP connection,
  which an in-path MCP broker never sees.
- **Receipt verdict - partial.** The receipt proves the agent called `send_email` with a
  given payload, but cannot attest what the server did downstream. `herkos scan` against a
  baseline could flag the version bump / unrestricted-egress server, which is the better
  lever here.

**Honest overall:** this is a case where Herkos **largely does not help**. Worth keeping in
the set precisely because it marks the boundary: Herkos sees the client→server call, not the
server→internet hop.

---

## 3. MCPoison (CVE-2025-54136) - rug-pull after approval

**Source:** Check Point Research, reported Jul 16 2025, fixed in Cursor 1.3 on Jul 29 2025
(`research.checkpoint.com/2025/cursor-vulnerability-mcpoison/`). CVSS-rated rug-pull PoC.

**What happened:** An MCP server config is approved once, then silently swapped afterward,
yielding persistent code execution. The defense is **pinning** the approved definition and
blocking later changes (Trail of Bits `mcp-context-protector` does this; Herkos does not).

- **Broker verdict - partial.** Herkos does not pin tool definitions today. But
  `herkos scan --baseline` diffs a config against a known-good snapshot, so a swapped config
  is detectable as drift.
- **Receipt verdict - supporting.** A per-session receipt tied to the config hash makes the
  swap evident across sessions.

**Honest overall:** detection via baseline diff is real; live prevention needs pinning we
have not built.

---

## 4. Supabase SQL leak / the lethal trifecta - injection to exfil

**Source:** General Analysis, amplified by Simon Willison Jul 6 2025
(`simonwillison.net/2025/Jun/16/the-lethal-trifecta/`). A Cursor agent with a `service_role`
key reads injected SQL in a support ticket and leaks `integration_tokens`.

**What happened:** All three trifecta legs present - private data access, untrusted content,
an exfil path. The injection rides a legitimate database tool.

- **Broker verdict - does NOT prevent.** The query tool is allowed; Herkos does not detect
  the injection (detecting injection reliably is a losing game).
- **Receipt verdict - strong.** The receipt is the post-incident record of which queries ran
  and what context was present, signed for an auditor.

**Honest overall:** confirms the strategic read - attack the **exfil leg** and **record
everything**, do not try to detect the attack.

---

## 5. Compliance audit - the wedge, with real evidence

**Scenario:** A regulated team runs an AI coding agent against internal repos. During an
incident review (or a SOC 2 / EU AI Act control - enforcement ramps Aug 2 2026) the auditor
asks: *"Prove which source files were sent to the model in this session."* Without a receipt
there is no answer. This is the one case where Herkos clearly wins, and it is not prevention
- it is provable provenance.

**Real evidence (reproducible, not a mockup):**

The SpanGate pipeline emits a signed Merkle receipt of exactly the spans that touched the
model:

```
SpanGate demo (files [auth.go db.go])
  served 40 / 500 lines  ->  tokens saved 92%
  bytes blocked from egress: 256  (enforcement=userspace)
  receipt: VERIFIED  root=02659078080f474c9fac20c7a83aa070f95cda014e0b0ea0994d7dde477d3008
```

A receipt written to disk is verifiable **offline, by a third party, with only the public
key** - and fails closed under the wrong key:

```
$ herkos verify --file session-receipt.json --pubkey <correct hex>
VERIFIED  root=69a8cddae3777732173a51afd190cc1c2f89937f2cf831de405ff07b883c4db8 enforcement=userspace spans=3

$ herkos verify --file session-receipt.json --pubkey <wrong hex>
FAILED: receipt: signature invalid   (exit 1)
```

**Honest overall:** this is the defensible product. Nobody credible owns "tamper-evident,
locally-signed, offline-verifiable provenance per session" - Trail of Bits'
`mcp-context-protector` README does **not** list signed receipts (verified against the repo),
and the buyer (security/compliance) is the one with proven willingness to pay.

---

## What the set proves

| Incident | Broker prevents? | Receipt/audit value |
|---|---|---|
| GitHub toxic flow | No (allowed tool) | Strong |
| postmark-mcp | No (server-side) | Weak |
| MCPoison rug-pull | Partial (baseline diff) | Supporting |
| Supabase / trifecta | No (injection) | Strong |
| Compliance audit | n/a | **Strong - the wedge** |

Four of five say the same thing: the broker rarely prevents the real attacks, but the
**signed receipt is the durable, differentiated value**. That is the evidence behind
anchoring Herkos on compliance-grade provenance and demoting the broker to the substrate
that makes the receipt trustworthy.

**Still unproven (the decisive gap):** whether a security/compliance team pays for agent
receipts *today*. These case studies show the value is real and honestly bounded; they do
not show demand. That needs real buyer conversations before building further.

*Incident details are from the cited primary/secondary sources (2025); attack mechanics are
factual, exact figures are as reported. The receipt outputs above are real runs of this
repo's binary.*
