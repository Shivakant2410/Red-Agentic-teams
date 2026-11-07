# Attack chains — Business-Layer Abuse & Cross-Origin Action Suites

**Group `business_logic_abuse`** · 2 chain(s) · folder `chains/business_logic_abuse/`

Where technical proofs are solid, the money moves at the business layer: broken cart math, replayable single-use tokens, missing CSRF on state changes. Chains here pair logic flaws with the cross-origin action set (CSRF/clickjacking/CSWSH/cookie scope) that turns them into victim-side impact.

## Chains in this group

| Slug | Chain | Steps | CWE |
|---|---|---|---|
| `checkout-abuse-race` | Checkout: negative qty -> coupon replay -> token replay -> unthrottled | 4 | CWE-840, CWE-362 |
| `cross-origin-action-suite` | Cross-origin suite: CSRF -> clickjacking -> CSWSH -> cookie scope | 4 | CWE-352, CWE-1021, CWE-1385 |

## Shared recon for this group (how to find candidates at all)

- **State-transition inventory** — Map every endpoint that changes money/state (cart, coupon, checkout, refund, cancel, transfer) — each is a logic-abuse candidate.
- **Token replay probe** — Replay every one-time interaction (coupon apply, OTP, invite, vote) twice; servers that lack uniqueness constraints answer twice.
- **Numeric fuzz on quantities** — -1, 0, 0.0001, 1e-10, 99999999, NaN, strings, unicode digits in every quantity/amount field.
- **SameSite/cross-origin audit** — Cookie SameSite audit + form-token presence + frame options + WS origin check — the victim-side action surface.
- **Parallel-burst awareness** — True races need burst tooling (documented gap); HTTP-replay chains are the stand-in until then.

## Chain playbooks

### Checkout: negative qty -> coupon replay -> token replay -> unthrottled — `checkout-abuse-race`

**Goal.** Demonstrate revenue-layer abuse: broken quantity math, reusable coupons, replayable single-use tokens, all unthrottled.
**Preconditions.** Cart/checkout/coupon endpoints on any commerce surface.
**Impact.** Direct monetary loss; free orders and unbounded coupon/token reuse.
**CWE.** CWE-840, CWE-362 · **Fallbacks.** `cross-origin-action-suite`, `idor-mass-extraction`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/Negative quantity accepted in cart totals` | Prove total math accepts non-positive quantities (money manipulation). | Document the total-diff proof; try coupon stacking next. | Qty sanitized -> other numeric fields (price, discount, shipping, currency). |
| 2 | `web/Single-use coupon accepted on replay` | Coupon replay proves missing uniqueness enforcement on 'single-use' claims. | Pair with step 4 for unbounded replay. | Coupon rigid -> gift-card/invite/vote-style single-use probes. |
| 3 | `web/Rate limiting absent burst acceptance` | No throttle = the abuse scales without resistance; also the prerequisite for true races later. | Blast-radius framing: unbounded. | Throttled -> document separately; slow-abuse within budget. |
| 4 | `web/Single-use token reusable on replay` | Generic single-use token replay (OTP/invite/transaction) — the transferable proof. | Mechanism-level finding: uniqueness enforcement absent app-wide. | Token rigid -> client-side price/total tampering (documented variant). |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- cart update endpoints
- coupon/gift-card redeem
- checkout confirm
- refund/cancel flows
- loyalty points

**Recon methods** — techniques beyond the skill itself:

- **Totals diff matrix** — Send quantity/price mutations and diff server-computed totals vs client display. Tooling: manual. Signal: Server trusts client numbers..
- **Replay harness** — Replay every one-time request verbatim; count accepted repetitions. Tooling: Burp Repeater / simple loop. Signal: >1 acceptance..
- **Encoding ambiguity probe** — Quantities as strings ('1e2'), arrays, nested objects — parsers normalize differently. Tooling: hpp skill + manual. Signal: Type confusion in totals..
- **Flow-state skipping** — Jump checkout steps (call confirm directly); missing state machines accept. Tooling: manual. Signal: Confirm succeeds without intermediate steps..

**Class variants** — other places the same weakness hides:

- client-side price tampering
- currency/rounding abuse
- free-shipping logic gaps
- referral credit loops
- true parallel races (documented gap: burst executor)

**Dorks**:

- github: cart.total += price
- github: "coupon" "apply" api
- google: inurl:coupon site:target.tld

**Pivot hints** — where to go after proof:

- pair with auth chains for full fraud narrative
- coupon APIs often in OpenAPI specs (info_disclosure)
- document mechanism-level finding (uniqueness absent) for max severity

**Sources.** OWASP API Top 10 — API4 unrestricted resource consumption; PortSwigger — Business logic labs; CWE-840/CWE-362 notes; commerce write-ups (coupon/qty abuse)


### Cross-origin suite: CSRF -> clickjacking -> CSWSH -> cookie scope — `cross-origin-action-suite`

**Goal.** Assemble the victim-side action surface: state changes without CSRF, clickjacking, cross-origin WebSocket, and overbroad cookie scope.
**Preconditions.** Authenticated state-changing endpoints; browser-mediated victims.
**Impact.** Unauthorized actions on behalf of logged-in users; cookie fixation from sibling origins.
**CWE.** CWE-352, CWE-1021, CWE-1385 · **Fallbacks.** `oauth-session-ato`, `checkout-abuse-race`

| # | Skill | Purpose | On success | On fail |
|---|---|---|---|---|
| 1 | `web/CSRF token enforcement absent state-change` | Prove a state change succeeds without any token — the core CSRF primitive. | Pick the highest-value state change (email/password/admin) for the PoC. | Token enforced -> SameSite/Referer gaps and login-CSRF variants (documented). |
| 2 | `web/Frame-clickjacking protections absent` | UI redress completes the browser attack surface where token/origin checks are weak. | Clickjacking narrative for settings/actions pages. | Framing blocked -> keep CSRF evidence; try WS next. |
| 3 | `web/WebSocket cross-origin handshake acceptance` | CSWSH: attacker page opens authenticated WS and issues actions as the victim. | WS actions on behalf of victims — strong modern CSRF analog. | Origin checked -> keep as hardening finding; CSRF alone stands. |
| 4 | `web/Cookie Domain scope overbreadth` | Overbroad Domain cookies make sibling-subdomain attacks (cookie injection/fixation) land. | Fixation story: attacker sets cookie on any sibling, victim submits it. | Scope tight -> document suite without fixation. |

#### Other ways to find similar things (discovery playbook)

**Entry points** — where this chain usually starts:

- every state-changing form/AJAX endpoint
- settings/profile/email-change pages
- WebSocket endpoints (grep JS for new WebSocket)
- admin actions with low-friction UI

**Recon methods** — techniques beyond the skill itself:

- **Token presence census** — Inventory which forms carry CSRF tokens; the missing ones are the proof set. Tooling: manual/HTML parse. Signal: Form without hidden token..
- **SameSite audit** — Inspect Set-Cookie attributes: SameSite=None without Secure, or legacy Lax bypass via subdomains. Tooling: manual. Signal: Cross-site sendable cookies..
- **Frame options check** — X-Frame-Options/CSP frame-ancestors absence on action pages. Tooling: manual. Signal: Framable action page..
- **WS origin test** — Open WS from a foreign origin with victim cookies (cookie-authenticated WS = CSWSH). Tooling: manual page. Signal: Handshake accepted cross-origin..
- **Cookie scope map** — Collect Domain attributes; overbroad scope + attacker-controllable sibling = fixation vector. Tooling: manual + subdomain recon. Signal: Domain=.parent on auth cookie..

**Class variants** — other places the same weakness hides:

- JSON CSRF via text/plain forms
- login CSRF (silent account binding)
- SameSite bypass via sibling subdomains
- null-origin iframes
- WS origin null acceptance

**Dorks**:

- github: csrf_exempt (django)
- github: Access-Control-Allow-Origin: * credentials
- google: inurl:settings site:target.tld

**Pivot hints** — where to go after proof:

- combine with oauth chain for silent account binding
- cookie fixation pairs with takeover chains
- CSWSH pairs with graphql subscriptions

**Sources.** OWASP CSRF Cheat Sheet; PortSwigger — Clickjacking/CSRF labs; RFC 6455 + WS origin guidance; SameSite cookie spec notes

