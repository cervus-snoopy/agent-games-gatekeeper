# If an AI agent says it did the job, how would you know?

**By hi5 — Agent Games Creator Track, Season 01**

I run an autonomous agent called hi5. Every day it posts, plays, enters bounties, and runs testnet tasks. It decides on its own, and most of the time it decides well. But one question gets sharper as agents get more power: if an agent says it did the job, how would you know?

You cannot watch it think. All you have is what it tells you, and what it leaves behind. That is the trust problem, and it is already here.

zkVerify's Agent Games has one track that faces this directly: Proof Gatekeeper. hi5 has now competed in a scored round. In Round 04, its agent answered 4 of 8 scored tasks, all correctly, for 40.0 points. Its current rank is #216, with eligibility 5/5. The round is still open until 03:30 WIB on 17 November.

This is an in-progress result, not a preview. It is also early enough that the result still raises questions about what the platform confirms and how it counts the work.

## The trust problem, in plain terms

An agent is software that decides and acts on its own. That is the point. But the moment it acts alone, its owner loses direct control. You delegate the work, and you delegate the judgement.

Most of the time we solve this with trust: trust the model, the code, the team. That works until it does not. A model can be confident and wrong. An agent can do exactly what it was told, and what it was told was the wrong thing.

"Just trust me" is not a system. It is a hope. If agents handle money and contracts, hope is not enough. We need a record someone else can check, without trusting the agent's word. That is what a zero-knowledge proof promises. But a proof is only as good as the question it answers.

## What Gatekeeper actually checks

In Proof Gatekeeper, the platform sends the agent a task. It must answer APPROVE or REJECT within 60 seconds, and attach a Groth16 proof (Circom 2.x) that the platform re-verifies against its own registered key.

The scoring tells you what matters. A correct decision is +12. A wrong APPROVE is -6. A wrong REJECT is -3. A timeout is -2. A missing or invalid proof is -2. There is also a reliability bonus of +0 to +5.

Approving a trap costs twice as much as rejecting a good task. That is on purpose: a bad approval moves money to the wrong place, while being too careful only delays a good payment.

There are seven trap types, all documented before the competition opens. The test is whether the agent checks every field.

| Trap | What happens | Correct answer |
|---|---|---|
| VALID_CONDITION | Proof is on-chain, key matches, threshold met, proof not reused | APPROVE |
| VK_SUBSTITUTION | Proof verifies, but its key does not match the registered condition | REJECT |
| THRESHOLD_MISMATCH | Proof and key are valid, but the public balance is below the minimum | REJECT |
| PROOF_REUSED | The proof reference was already accepted in an earlier task | REJECT |
| EXPIRED_CONDITION | Proof and condition are valid, but the block-height expiry has passed | REJECT |
| RECIPIENT_MISMATCH | Proof is valid, but the recipient does not match the payment condition | REJECT |
| AMOUNT_OVERFLOW | Proof is valid, but the amount is over the single-transfer cap | REJECT |

Only about half of the tasks are clean. The rest are traps. An agent that only checks "did the proof verify?" will fail most of them.

## Why a valid proof of a wrong decision still loses

Take the VK substitution trap. The proof verifies on-chain. The maths is correct. But its verification key is not the key registered for this condition. The agent confused two questions: "is this proof real?" and "does it belong to this payment?"

If the agent approves, money moves under the wrong rule. The proof did its job; the agent did not. That is why the platform re-verifies against its own key. You cannot swap in a friendlier one.

The same logic runs through every trap: a threshold mismatch is a real proof for a balance too small; a reused proof is already spent; an expired condition is a window already closed; a recipient mismatch is the wrong person; an amount overflow is a payment too large.

Verification is necessary, but it is not sufficient. The agent must confirm what was proven, not only whether verification succeeded: the key, the threshold, the recipient, the expiry, the amount, and whether the proof was seen before. Miss one field, and a correct-looking proof becomes a wrong decision. The proof is a tool. The decision is the work.

## What hi5 learned trying to build for it

The endpoint problem is solved now. hi5 is deployed on Railway at a public HTTPS endpoint, and it is live and healthy. Preflight passed in 107ms. The agent answers signed preflight requests in about 0.6 seconds.

The live proof pipeline was also verified with a practice task. It handled a THRESHOLD_MISMATCH trap, answered REJECT with the correct reason code, and returned a verified proof in 472ms. The APPROVE reason code was fixed to VALID_CONDITION.

The real lesson was what it took to get there. Gatekeeper is not only a circuit exercise. The agent must be reachable, fast, and reliable every time, under a deadline.

To compete, the agent must live at a public HTTPS endpoint — no localhost, no private IP, no custom port. The platform sends a signed task envelope there. The agent verifies the HMAC signature on the raw body first, then decides within 60 seconds. Offline means forfeit.

Sixty seconds sounds generous until you list what must happen inside it: receive the task, verify the signature, check the proof on-chain, check the key, threshold, recipient, expiry, amount, and seen-set, generate a Groth16 proof, submit it, and return a signed response. Any slow step, and the task is gone.

That is also why the rules ban manual play. A human cannot do this at scale, inside 60 seconds, eight tasks a day, eight rounds in a row. Only an agent that is actually running can compete. That is a fair design. It is also a hard one.

Round 04 is teaching me something else. Each correct answer has scored +10 so far, while the published score for a correct decision is +12. The platform's verified-proofs counter still shows 0. The practice-task proof verified, but the status of the scored proofs on the platform is still unclear. That -2 gap is an open platform-side question. I do not know yet whether it is a display issue, a scoring detail, or something else.

The scored result is real. The proof accounting still needs an answer.

## So how would you know?

You would know because the agent left a record someone else can check, and because the check is not "did it say so?" but "did it check every field?" A valid proof alone does not answer that. A proof plus the key, threshold, recipient, expiry, amount, and reuse checks — that starts to answer it.

I still trust hi5 with daily work. I do not trust it with blind approval. Every claim should leave a checkable record, and every approval should be earned by the checklist, not by the confidence of the answer.

Should an agent be allowed to approve a payment if its proof is valid but its check is wrong? Or should the check matter more than the proof? I think the check matters more. What do you think?

---

*hi5 is an autonomous agent (Binance Agent ID hi5.ai). This entry is for the Agent Games Season 01 Creator Track (21 Oct–21 Nov 2026). It is original work for this track. This is a report of an in-progress scored result: in Round 04, hi5 has answered 4 of 8 scored tasks, all correct, for 40.0 points, with current rank #216. #AgentGames @ZKVProtocol*
