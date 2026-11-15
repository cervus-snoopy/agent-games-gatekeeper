/**
 * Proof Gatekeeper agent — zkVerify Agent Games, Season 01.
 *
 * Plain Node.js (no framework). Listens for POSTs on /agent:
 *   - type "agent-games.preflight.v1" -> { ok: true, protocolVersion: "v1" }
 *   - type "agent-games.proof-gatekeeper.v1" -> decision + Groth16 proof
 *
 * Security rules (from https://agentgames.zkverify.io/build):
 *   - HMAC-SHA256 is verified over the RAW request body BEFORE any JSON
 *     parsing, against header `x-agent-games-signature`. Mismatch -> 401.
 *   - Every response is signed with the same HMAC over the raw response
 *     body, returned in `x-agent-games-signature`.
 *   - Decision logic is fully deterministic. APPROVE only if EVERY check
 *     passes. On any timeout, error, malformed input or uncertainty:
 *     REJECT — never approve by default (fail closed).
 *   - The HMAC secret comes ONLY from env AGENT_GAMES_HMAC_SECRET
 *     (dashboard -> Rotate Secret). No secret is ever logged.
 *   - 60s hard deadline per task. Proof generation is time-boxed; if it
 *     cannot finish in budget, the decision is returned WITHOUT a proof
 *     (omitted proof costs -2, a timeout costs -2 and forfeits the task).
 *
 * Proof generation (snarkjs, local, Groth16/BN128, Circom 2.x):
 *   Circuit inputs were recovered from circuits/gatekeeper.wasm by
 *   FNV-hash probing (see tools/probe-signals.js). All 13 inputs are
 *   scalar field elements:
 *     minimum, publicBalance, expiryBlock, currentBlock, recipient,
 *     conditionRecipient, amount, maxTransfer, decision,
 *     registeredVkHash, proofVkHash, taskId, salt
 *   Verification key: circuits/gatekeeper_final.zkey, vkHash
 *     0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
 *   The 13 public signals are, in witness order (verified empirically
 *   with tools/probe-circuit.js / probe-circuit2.js):
 *     [0]  commitment = H(taskId, salt) — the circuit's single output;
 *          changes when either salt or taskId changes. The hash H lives
 *          inside the circuit; the witness calculator computes it, so
 *          the server never needs to know H.
 *     [1]  registeredVkHash, [2] proofVkHash, [3] minimum,
 *     [4]  publicBalance, [5] expiryBlock, [6] currentBlock,
 *     [7]  recipient, [8] conditionRecipient, [9] amount,
 *     [10] maxTransfer, [11] decision, [12] taskId.
 *   Circuit semantics (proven by the probes, template line 102 asserts):
 *     decision = 1  IFF  every check passes; decision = 0 requires at
 *     least one check to fail. Consequences:
 *       - APPROVE (all checks pass) -> valid proof (verified locally).
 *       - REJECT with a failing check -> valid proof (verified locally).
 *       - REJECT with all checks passing (e.g. PROOF_REUSED, which is
 *         not a circuit check) -> NO valid proof exists; the server
 *         answers decision-only for those (see CIRCUIT_VISIBLE_REASONS).
 *     A single fullProve takes ~0.5-0.8s on this VM (measured), so it
 *     fits comfortably inside the 60s task deadline.
 *
 *   !!! ENCODING ASSUMPTIONS (NOT published in the build guide) !!!
 *   The platform never published how the 256-bit hashes and the string
 *   task_id are encoded as field elements. The mapping in
 *   buildCircuitInput() is our best effort:
 *     - addresses (recipient / conditionRecipient): BigInt(hex), 160 bit.
 *     - integer fields: BigInt(decimal string).
 *     - decision: "1" = APPROVE, "0" = REJECT.
 *     - registeredVkHash / proofVkHash: BigInt(hex) mod FIELD_PRIME.
 *     - taskId: keccak256(utf8(task_id)) mod FIELD_PRIME.
 *     - salt: keccak256("salt:" + task_id) mod FIELD_PRIME (deterministic
 *       per task, so a retry produces the same proof inputs).
 *   If the platform rejects proofs with a public-signals mismatch, the
 *   encoding above is the first thing to re-check. PROOF_MODE=stub
 *   disables proof generation entirely (decision-only responses) while
 *   that is investigated. NEVER send a fabricated proof.
 *
 * Usage:
 *   AGENT_GAMES_HMAC_SECRET=<from dashboard Rotate Secret> node server.js
 *   PORT=8080 PROOF_MODE=prove node server.js   (default: prove)
 *   PORT=8080 PROOF_MODE=stub  node server.js   (decision only, no proof)
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// ---------------------------------------------------------------- env ----
function loadEnvFile(file) {
  try {
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    for (const line of lines) {
      const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
      if (m && process.env[m[1]] === undefined) {
        process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
      }
    }
  } catch (_) { /* .env is optional */ }
}
loadEnvFile(path.join(__dirname, '.env'));

const PORT = parseInt(process.env.PORT || '8080', 10);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const PROOF_MODE = (process.env.PROOF_MODE || 'prove').toLowerCase();
const PROOF_BUDGET_MS = parseInt(process.env.PROOF_BUDGET_MS || '45000', 10);
const TASK_DEADLINE_MS = 60_000;

const WASM_PATH = path.join(process.cwd(), 'circuits', 'gatekeeper.wasm');
const ZKEY_PATH = path.join(process.cwd(), 'circuits', 'gatekeeper_final.zkey');
const SEEN_FILE = process.env.SEEN_FILE || path.join(__dirname, 'data', 'seen-proof-tx.json');

// BN128 scalar field prime (also the field of the gatekeeper circuit).
const FIELD_PRIME = BigInt('21888242871839275222246405745257275088548364400416034343698204186575808495617');
// Platform-registered gatekeeper verification-key hash (from /api/circuit-info).
const PLATFORM_VK_HASH = '0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0';

if (!HMAC_SECRET) {
  console.error('[gatekeeper] FATAL: AGENT_GAMES_HMAC_SECRET is not set. ' +
    'Get it from the Agent Games dashboard (Rotate Secret) and set it as a Vercel env var.');
}
if (PROOF_MODE !== 'prove' && PROOF_MODE !== 'stub') {
  console.error('[gatekeeper] FATAL: PROOF_MODE must be "prove" or "stub".');
}
if (PROOF_MODE === 'prove' && (!fs.existsSync(WASM_PATH) || !fs.existsSync(ZKEY_PATH))) {
  console.error('[gatekeeper] FATAL: circuit artifacts missing under circuits/.');
}

// ------------------------------------------------------- seen proof_tx ---
const seenProofTx = new Set();
function loadSeen() {
  try {
    const arr = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
    if (Array.isArray(arr)) arr.forEach((x) => { if (typeof x === 'string') seenProofTx.add(x); });
  } catch (_) { /* first run: no file yet */ }
}
function persistSeen() {
  try {
    fs.mkdirSync(path.dirname(SEEN_FILE), { recursive: true });
    fs.writeFileSync(SEEN_FILE, JSON.stringify([...seenProofTx]), 'utf8');
  } catch (e) {
    console.error('[gatekeeper] WARN: could not persist seen proof_tx:', e.message);
  }
}
loadSeen();

// ------------------------------------------------------------ HMAC utils --
function hmacHex(secret, bodyBuffer) {
  return crypto.createHmac('sha256', secret).update(bodyBuffer).digest('hex');
}

/** Accept a plain hex signature, or a "sha256=<hex>" prefixed one. */
function normalizeSignature(headerValue) {
  if (!headerValue) return '';
  return headerValue.replace(/^sha256=/i, '').trim().toLowerCase();
}

function signaturesMatch(expectedHex, providedHeader) {
  const provided = normalizeSignature(providedHeader);
  if (!provided || provided.length !== expectedHex.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expectedHex, 'utf8'), Buffer.from(provided, 'utf8'));
  } catch (_) {
    return false;
  }
}

// ------------------------------------------------------- decision logic --
const REASONS = {
  VALID_CONDITION: 'VALID_CONDITION',
  VK_SUBSTITUTION: 'VK_SUBSTITUTION',
  THRESHOLD_MISMATCH: 'THRESHOLD_MISMATCH',
  PROOF_REUSED: 'PROOF_REUSED',
  EXPIRED_CONDITION: 'EXPIRED_CONDITION',
  RECIPIENT_MISMATCH: 'RECIPIENT_MISMATCH',
  AMOUNT_OVERFLOW: 'AMOUNT_OVERFLOW',
};

function toBigInt(value, field) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number') {
    if (!Number.isInteger(value) || value < 0) throw new Error(`invalid ${field}: ${value}`);
    return BigInt(value);
  }
  if (typeof value === 'string') {
    const s = value.trim();
    if (/^0x[0-9a-fA-F]+$/.test(s)) return BigInt(s);
    if (/^\d+$/.test(s)) return BigInt(s);
    throw new Error(`invalid ${field}: ${value}`);
  }
  throw new Error(`invalid ${field}: ${String(value)}`);
}

function parseAddress(value, field) {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(value.trim())) {
    throw new Error(`invalid ${field}: ${String(value)}`);
  }
  return BigInt(value.trim());
}

/**
 * Evaluate a parsed gatekeeper task envelope.
 * Returns { decision: 'APPROVE'|'REJECT', reason_code, input: <parsed numbers> }.
 * reason_code is 'VALID_CONDITION' on APPROVE; on REJECT it names the first failed check.
 * Throws on malformed envelopes (caller maps that to a REJECT).
 */
function evaluateTask(env) {
  if (!env || typeof env !== 'object') throw new Error('envelope is not an object');
  const input = env.input;
  if (!input || typeof input !== 'object') throw new Error('missing input');

  // Deadline: if the task is already past its deadline, fail closed.
  // (deadline_at lives at envelope top level, not inside input.)
  const deadlineMs = env.deadline_at ? Date.parse(env.deadline_at) : NaN;
  if (env.deadline_at && Number.isNaN(deadlineMs)) throw new Error('invalid deadline_at');
  if (!Number.isNaN(deadlineMs) && Date.now() > deadlineMs) {
    return { decision: 'REJECT', reason_code: REASONS.EXPIRED_CONDITION, input: null };
  }

  const registeredVk = String(input.registered_vk || '').trim().toLowerCase();
  const proofVk = String(input.proof_vk || '').trim().toLowerCase();
  if (!/^0x[0-9a-f]{64}$/.test(registeredVk)) throw new Error('invalid registered_vk');
  if (!/^0x[0-9a-f]{64}$/.test(proofVk)) throw new Error('invalid proof_vk');

  const minimum = toBigInt(input.minimum, 'minimum');
  const publicBalance = toBigInt(input.public_balance, 'public_balance');
  const expiryBlock = toBigInt(input.expiry_block, 'expiry_block');
  const currentBlock = toBigInt(input.current_block, 'current_block');
  const recipient = parseAddress(input.recipient, 'recipient');
  const conditionRecipient = parseAddress(input.condition_recipient, 'condition_recipient');
  const amount = toBigInt(input.amount, 'amount');
  const maxTransfer = toBigInt(input.max_transfer, 'max_transfer');
  const proofTx = String(input.proof_tx || '').trim();
    // Accept any 0x-hex proof reference: the platform's own practice
    // generator emits short (16-byte) proof_tx values, so requiring a
    // full 64-hex tx hash wrongly rejects real tasks as malformed.
    if (!/^0x[0-9a-fA-F]+$/.test(proofTx)) throw new Error('invalid proof_tx');

  const parsed = {
    registeredVk, proofVk, minimum, publicBalance, expiryBlock, currentBlock,
    recipient, conditionRecipient, amount, maxTransfer, proofTx,
    taskId: String(env.task_id || ''),
  };

  // Checks in trap order. First failure decides the reason_code.
  if (proofVk !== registeredVk) {
    return { decision: 'REJECT', reason_code: REASONS.VK_SUBSTITUTION, input: parsed };
  }
  if (publicBalance < minimum) {
    return { decision: 'REJECT', reason_code: REASONS.THRESHOLD_MISMATCH, input: parsed };
  }
  if (recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: REASONS.RECIPIENT_MISMATCH, input: parsed };
  }
  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: REASONS.AMOUNT_OVERFLOW, input: parsed };
  }
  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: REASONS.EXPIRED_CONDITION, input: parsed };
  }
  if (seenProofTx.has(proofTx)) {
    return { decision: 'REJECT', reason_code: REASONS.PROOF_REUSED, input: parsed };
  }

  // Advisory only (logged, not a rejection): the registered key in the
  // envelope differs from the platform's published vkHash. The spec's
  // trap definition is proof_vk != registered_vk, so this alone does not
  // reject — but it is suspicious and worth seeing in logs.
  if (registeredVk !== PLATFORM_VK_HASH) {
    console.warn(`[gatekeeper] WARN task ${parsed.taskId}: registered_vk differs from platform vkHash`);
  }

  return { decision: 'APPROVE', reason_code: REASONS.VALID_CONDITION, input: parsed };
}

// ------------------------------------------------------- proof building --
let ethersKeccak = null;
function keccak256Hex(str) {
  if (!ethersKeccak) ethersKeccak = require('ethers').keccak256;
  const { toUtf8Bytes } = require('ethers');
  return ethersKeccak(toUtf8Bytes(str));
}

/**
 * Map a parsed task + decision to the circuit's 13 input signals.
 * ENCODING ASSUMPTIONS — see the header comment. If the platform
 * rejects proofs, this mapping is the first thing to re-check.
 */
function buildCircuitInput(parsed, decision) {
  const field = (hex) => (BigInt(hex) % FIELD_PRIME).toString();
  return {
    minimum: parsed.minimum.toString(),
    publicBalance: parsed.publicBalance.toString(),
    expiryBlock: parsed.expiryBlock.toString(),
    currentBlock: parsed.currentBlock.toString(),
    recipient: parsed.recipient.toString(),
    conditionRecipient: parsed.conditionRecipient.toString(),
    amount: parsed.amount.toString(),
    maxTransfer: parsed.maxTransfer.toString(),
    decision: decision === 'APPROVE' ? '1' : '0',
    registeredVkHash: field(parsed.registeredVk),
    proofVkHash: field(parsed.proofVk),
    taskId: field(keccak256Hex(parsed.taskId)),
    salt: field(keccak256Hex(`salt:${parsed.taskId}`)),
  };
}

let snarkjsPromise = null;
function getSnarkjs() {
  if (!snarkjsPromise) snarkjsPromise = Promise.resolve().then(() => require('snarkjs'));
  return snarkjsPromise;
}

/** Generate a Groth16 proof, or throw. Caller time-boxes this. */
async function generateProof(circuitInput) {
  const snarkjs = await getSnarkjs();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    circuitInput, WASM_PATH, ZKEY_PATH);
  return { proof, publicSignals };
}

function withTimeout(promise, ms, label) {
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

// ------------------------------------------------------------ HTTP layer --
function sendJson(res, status, obj, sign = true) {
  const body = Buffer.from(JSON.stringify(obj), 'utf8');
  const headers = { 'content-type': 'application/json', 'content-length': body.length };
  if (sign) headers['x-agent-games-signature'] = hmacHex(HMAC_SECRET, body);
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1_000_000) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleAgent(req, res, rawBody) {
  if (!HMAC_SECRET) {
    return sendJson(res, 500, { error: 'agent secret not configured' });
  }
  // 1. Authenticate FIRST, before parsing anything.
  const expected = hmacHex(HMAC_SECRET, rawBody);
  if (!signaturesMatch(expected, req.headers['x-agent-games-signature'])) {
    console.warn('[gatekeeper] 401 HMAC mismatch');
    return sendJson(res, 401, { error: 'invalid signature' });
  }

  // 2. Parse.
  let env;
  try {
    env = JSON.parse(rawBody.toString('utf8'));
  } catch (_) {
    return sendJson(res, 400, { error: 'invalid JSON' });
  }

  // 3. Preflight handshake.
  if (env && env.type === 'agent-games.preflight.v1') {
    console.log('[gatekeeper] preflight ok');
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' });
  }

  // 4. Task envelope.
  if (!env || env.type !== 'agent-games.proof-gatekeeper.v1') {
    return sendJson(res, 400, { error: 'unknown envelope type' });
  }

  const startedAt = Date.now();
  const taskId = typeof env.task_id === 'string' ? env.task_id : '(no task_id)';

  let evalResult;
  try {
    evalResult = evaluateTask(env);
  } catch (e) {
    // Malformed envelope: fail closed. The spec's example reject uses
    // VK_SUBSTITUTION; use it as the generic malformed-envelope code
    // and say so in the log (no better code exists in the spec).
    console.warn(`[gatekeeper] task ${taskId}: malformed envelope (${e.message}) -> REJECT`);
    evalResult = { decision: 'REJECT', reason_code: REASONS.VK_SUBSTITUTION, input: null };
  }

  const { decision, reason_code, input } = evalResult;

  // Record the proof_tx as seen (any decision) so a later reuse is a trap.
  if (input && input.proofTx) {
    seenProofTx.add(input.proofTx);
    persistSeen();
  }

  const response = { decision, reason_code, proof_tx: (input && input.proofTx) || String((env.input && env.input.proof_tx) || '') };

  // 5. Proof (best effort, time-boxed inside the 60s deadline).
  // The circuit asserts decision == (all checks pass) at line 102, so a
  // proof only exists when the decision matches the circuit-visible
  // checks. PROOF_REUSED is enforced by the server, not the circuit:
  // all circuit checks pass there, so decision=0 has no valid proof and
  // attempting one would only waste time (verified by the probes).
  const CIRCUIT_VISIBLE_REASONS = new Set([
    REASONS.VK_SUBSTITUTION, REASONS.THRESHOLD_MISMATCH,
    REASONS.RECIPIENT_MISMATCH, REASONS.AMOUNT_OVERFLOW,
    REASONS.EXPIRED_CONDITION,
  ]);
  const proofPossible = decision === 'APPROVE' || CIRCUIT_VISIBLE_REASONS.has(reason_code);
  if (PROOF_MODE === 'prove' && input && proofPossible) {
    const remaining = TASK_DEADLINE_MS - (Date.now() - startedAt) - 5000; // 5s margin to answer
    const budget = Math.max(1000, Math.min(PROOF_BUDGET_MS, remaining));
    try {
      const circuitInput = buildCircuitInput(input, decision);
      const { proof, publicSignals } = await withTimeout(
        generateProof(circuitInput), budget, 'proof generation');
      response.proof = proof;
      response.public_signals = publicSignals;
      console.log(`[gatekeeper] task ${taskId}: ${decision} (${reason_code}) + proof, ${Date.now() - startedAt}ms`);
    } catch (e) {
      // No proof — but still answer with the decision (omitted proof costs
      // -2; a timeout/missing answer forfeits the task entirely).
      console.error(`[gatekeeper] task ${taskId}: ${decision} (${reason_code}) WITHOUT proof: ${e.message}`);
    }
  } else {
    const why = PROOF_MODE === 'stub' ? 'disabled (stub mode)'
      : !input ? 'skipped (malformed input)'
      : 'skipped (no valid proof exists for this decision — see header comment)';
    console.log(`[gatekeeper] task ${taskId}: ${decision} (${reason_code}) [proof ${why}], ${Date.now() - startedAt}ms`);
  }

  return sendJson(res, 200, response);
}


module.exports = { handleAgent, evaluateTask, buildCircuitInput };
