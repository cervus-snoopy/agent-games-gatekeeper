# agent-games-gatekeeper

Proof Gatekeeper agent for **zkVerify Agent Games, Season 01** — handle `hi5`
(wallet `0xe0cec24b3e9698ec5d3eb97f53a1d18311bd165e`, GitHub `cervus-snoopy`).

A public HTTPS endpoint that receives signed task envelopes from the
Agent Games platform, decides APPROVE / REJECT with fully deterministic
rules (fail closed), and returns a locally generated Groth16 proof
(snarkjs, Circom 2.x, BN128) plus public signals.

- `POST /api/agent` — task envelopes (`agent-games.proof-gatekeeper.v1`)
  and the preflight handshake (`agent-games.preflight.v1`).
- HMAC-SHA256 verified over the raw request body before parsing
  (`x-agent-games-signature`); every response is signed the same way.
- Decision logic: APPROVE only when every check passes (VK match,
  threshold, recipient, amount, expiry, no proof reuse). Otherwise
  REJECT with a `reason_code` (`VK_SUBSTITUTION`, `THRESHOLD_MISMATCH`,
  `PROOF_REUSED`, `EXPIRED_CONDITION`, `RECIPIENT_MISMATCH`,
  `AMOUNT_OVERFLOW`). Fail closed on any error or timeout.
- Circuit inputs were recovered from `circuits/gatekeeper.wasm`
  (see the original build in `gatekeeper-agent/`).

## Deploy (Vercel)

1. Import this repo into Vercel (framework: Other / Node.js).
2. Set env var `AGENT_GAMES_HMAC_SECRET` to the secret from the
   Agent Games dashboard (My Agents → Rotate Secret). Optional:
   `PROOF_MODE=prove` (default), `PROOF_BUDGET_MS=45000`.
3. Deploy. The endpoint is `https://<deployment>/api/agent`.
4. Register that URL as the agent endpoint in the Agent Games
   dashboard and run preflight.

## Local test

The same logic lives in `gatekeeper-agent/` (plain Node server) with a
15-case harness (`node test/harness.js`) and an end-to-end proof check
(`node tools/e2e-verify.js`).
