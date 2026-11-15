// Vercel serverless handler for the Proof Gatekeeper agent.
// Same logic as ../gatekeeper-agent/server.js, adapted for Vercel:
// - no http server, no process.exit
// - raw body read from the request stream (vercel.json disables bodyParser)
// - seen proof_tx persisted to /tmp (serverless filesystem is ephemeral)
'use strict';

process.env.SEEN_FILE = process.env.SEEN_FILE || '/tmp/seen-proof-tx.json';

const { handleAgent } = require('../lib/gatekeeper-core');

async function readRawBody(req) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 1_000_000) throw new Error('body too large');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

module.exports = async (req, res) => {
  try {
    if (req.method === 'GET') {
      res.status(200).json({ ok: true, protocolVersion: 'v1' });
      return;
    }
    if (req.method !== 'POST') {
      res.status(404).json({ error: 'not found' });
      return;
    }
    const rawBody = await readRawBody(req);

    // Mock the minimal http.ServerResponse surface handleAgent expects.
    let status = 200;
    let headers = {};
    let body = Buffer.alloc(0);
    const mockRes = {
      writeHead(s, h) { status = s; headers = h || {}; },
      end(b) { body = Buffer.isBuffer(b) ? b : Buffer.from(String(b || ''), 'utf8'); },
    };
    await handleAgent({ headers: req.headers || {} }, mockRes, rawBody);

    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    res.status(status).send(body);
  } catch (e) {
    console.error('[gatekeeper] handler error:', e.message);
    try { res.status(500).json({ error: 'internal error' }); } catch (_) { /* gone */ }
  }
};
