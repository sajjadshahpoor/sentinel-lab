# Email

Evidence: `maildir.zip` — 22 exported `.eml` messages from Lucie Martens' mailbox. Two are
malicious. The trick is to read **headers**, not bodies: parse every message and line up
`From` / `Reply-To` / `Return-Path` / `Received` / `Authentication-Results`.

```python
import zipfile, email, email.policy
z = zipfile.ZipFile("maildir.zip")
for n in sorted(x for x in z.namelist() if x.endswith(".eml")):
    m = email.message_from_bytes(z.read(n), policy=email.policy.default)
    print(m["Date"], m["From"], m["Return-Path"], m["Authentication-Results"])
```

### The two malicious messages
- **05.eml** — spoofs `accounts@hamilton.corp`, but `Return-Path`/`Reply-To` point to
  `secure-paymentdesk.test`; `Received` from `secure-paymentdesk.test [91.219.236.18]`;
  `spf=softfail`, `dkim=none`. (Earliest malicious message → 2026-11-11 13:52.)
- **06.eml** — the IBAN-change message inside the real `PO-88214` thread. `From`
  `tom.verhaegen@verhaegen-packaging**s**.test` (look-alike with an extra "s"); `Received` from
  `mail.verhaegen-packagings.test [185.220.101.47]`; `spf=fail`, `dkim=none`.

The genuine supplier (`verhaegen-packaging.test`, `203.0.113.20`) is `spf=pass`/`dkim=pass`.

## Email 1 — First contact (50)
Earliest of the two malicious messages (05.eml, 2026-11-11 13:52). **Answer = its exact subject
line** (`████`).

## Email 2 — Real sender domain (50)
The IBAN-change message's sender domain actually used = the look-alike (`████`, the
"packaging**s**" variant).

## Email 2 — Origin IP (100)
From that message's `Received` header: the receiving server address (`████`).

## Email 2 — SPF verdict (100)
From its `Authentication-Results`: one word (`████`).
