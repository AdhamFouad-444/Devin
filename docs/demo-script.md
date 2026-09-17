# Falcon Shield — 90-Second Demo Script

Live run of `run/demo.sh all` — portal :8001, voice :8020, Mission Control at
`http://localhost:8080/apps/mission-control/`. All attacks are scripted against
our own sandbox; nothing touches a real system.

Fallbacks (rehearse with them once): dashboard Approve/Deny button writes the
same decision event if the phone call fails; `attacks.jsonl` "golden" scenarios
are known to trigger; the recorded full run is the last resort.

---

**[0:00–0:12] Quiet dashboard.**

*(Mission Control full-screen. Threat map idle. The counter reads "600,000 —
attacks the UAE faces daily.")*

"What you're looking at is a mock UAE citizen portal — permit renewals, trade
licenses, the everyday services residents depend on. Six hundred thousand
attacks a day hit this country for real — that's 416 every second, and the
government is the number-one target. There aren't enough humans for that math.
So we built a swarm. Let's attack it."

**[0:12–0:35] Attack wave.**

*(Stage hand runs `python tools/attacker/attack.py --scenario sqli`. Arcs light
up on the map — simulated origins arcing toward the UAE. An incident card opens:
detected → triaged → `sqli`, severity high. The containment agent's line
appears in the swarm panel: source IP blocked.)*

"The wave is live. Watch the feed — the sentinel raised it, triage labelled it
SQL-injection, containment blocked the source. Seconds. Nobody touched
anything. In most SOCs this is a ticket that waits hours."

**[0:35–0:52] The patch.**

*(Swarm panel shows a patch agent — a Devin session — attach to the incident.
The incident card flips to `patch_pr` and a real GitHub PR link appears on the
dashboard.)*

"But blocking an IP doesn't fix the hole. So a patch agent — a live Devin
session — traced that exploit back to the vulnerable line of code and just
opened a pull request. That's the part no alerting tool does: it writes the
fix itself."

**[0:52–1:08] The phone rings on stage.**

*(Deploy is a high-impact action. The voice service sees the approval request —
and the presenter's phone rings. Put it on speaker.)*

"Deploying to production is high-impact — policy says a human decides. So the
swarm does the polite thing."

*(On speaker: "Hello, this is Falcon Shield. A SQL-injection campaign hit the
citizen portal — I've contained it and prepared the patch. Shall I deploy?")*

Presenter: "Yes."

*(Decision lands in the audit log; controller merges the PR and deploys.)*

**[1:08–1:20] Re-attack fails.**

*(Re-run the same attack — `attack.py --scenario sqli --verify`. The probe
comes back `BLOCKED`. The incident card goes green: `verified`.)*

"Same attack, fired again — blocked at the code level, not the perimeter.
Detected, contained, patched, verified — and exactly one human touch: one word
on a phone call."

**[1:20–1:30] Close.**

*(Leave the dashboard up: metrics panel — MTTD in seconds, attacks blocked,
patches merged, human touches: 1.)*

"Six hundred thousand attacks a day. A swarm that detects, contains, and fixes
the code itself — and asks permission by phone. Zero new hires. One hundred
percent auditable. Falcon Shield."

---

### Presenter notes

- The numbers quoted on stage are public: ~600,000/day (~416/sec) per the UAE
  cybersecurity chief; government = 30% of attacks per the Cyber Security
  Council. Full citations in `docs/pitch.md` / `SCOPE_OF_WORK.md` Appendix C.
- If the phone call doesn't connect (venue network), click **Approve** in the
  dashboard's call panel — it writes the identical decision event; narrate it as
  "same approval, second channel."
- If asked about safety: all traffic is simulated inside our sandbox
  (`X-Sim-Source` spoofed IPs); offensive action against external systems is a
  prohibited tier by design.
- If asked "is the AI in charge?": humans set the policy tiers, approve every
  high-impact action, and own the audit trail. The swarm eats the volume; the
  human keeps the authority.
