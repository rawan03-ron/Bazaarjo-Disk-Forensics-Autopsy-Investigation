# 🔍 Digital Forensic Disk Investigation Report: Bazaarjo Incident

**Lead Examiner:** Rawan Nasif Mahmoud Samrin  
**Program:** NCSC — Masar Cybersecurity Training (Digital Forensics & Incident Response)  
**Forensic Suite:** `Autopsy 4.14.0` (The Sleuth Kit)  
**Evidence Image:** `Evidence.E01` (`Sector Size: 512`, `Timezone: Asia/Amman`)  
**Classification:** `TLP:WHITE` — Educational & Forensic Portfolio Case Study  

---

## 1. Executive Summary & Recovered Flags

A forensic disk examination was conducted on workstation **`DESKTOP-327589T`** (`Evidence.E01`) belonging to developer **`Omar.work`** following a suspected breach at **Bazaarjo**. Analysis confirmed a targeted HR-themed spear-phishing intrusion (`HRUpdate.exe`) that established logon persistence via a scheduled task and compromised plaintext developer credentials (`Git` & `SSH`) alongside internal business planning documents.

| Investigation Artifact | Recovered Flag |
| :--- | :--- |
| **Malware Hosting IP** | `FLAG{104.28.223.21}` |
| **Malware Filename Delivered** | `FLAG{HRUpdate.exe}` |
| **On-Disk Application Trace Directory** | `FLAG{C:\Users\Omar.work\AppData\Roaming\HRApp}` |
| **Scheduled Task Path (Logon Persistence)** | `FLAG{\UpdateTask}` |
| **Plaintext Credential Store File** | `FLAG{C:\Users\Omar.work\.git-credentials}` |
| **Compromised SSH Private Key Path** | `FLAG{C:\Users\Omar.work\.ssh\id_rsa}` |
| **Targeted Business Document** | `FLAG{Q4_Planning.docx}` |

---

## 2. Investigation Methodology & Chain of Custody

To maintain strict forensic integrity and ensure a verifiable audit trail throughout the examination of **`Evidence.E01`**, the following procedures were enforced:

* **Cryptographic Hash Verification:** SHA-256 and MD5 hashes were verified upon ingest into **Autopsy `4.14.0`** to guarantee zero bit-level alteration of the forensic image.
* **Timezone & Clock Reconciliation:** Host timestamps were normalized using the configured `Asia/Amman` (`UTC+03:00` / `EEST`) offset to reconstruct an accurate chronological timeline across file system metadata, Prefetch artifacts, and email headers.
* **Structured Forensic Workflow:** Automated ingest modules (`Recent Activity`, `Keyword Search`, `Email Parser`, `Hash Lookup`) were executed first, followed by manual file-system and registry inspection of critical user profile directories (`C:\Users\Omar.work`).

![Autopsy Data Source Ingest & Email Extraction](images/01-autopsy-ingest-emails.png)

---

## 3. Technical Analysis & Forensic Evidence

### 3.1 Initial Access — Spear-Phishing Vector (`T1566.002`)
* **Evidence Source:** `/img_Evidence.E01/.../HR_Update_Notice.eml` (`message/rfc822`)
* **Findings:** The intrusion originated from a spoofed HR notification email sent by `hr@bazaarjo-careers.com` to `omar@bazaarjo.com` (`Subject: HR System Update - Action Required`, `Date: Sat, 11 Oct 2025 09:10:00 +0300`), instructing the victim to download and execute `http://104.28.223.21/HRUpdate.exe`.

![Spear-Phishing Email Evidence](images/02-phishing-email-evidence.png)

### 3.2 Payload Delivery & Execution Traces (`T1204.002`)
* **Downloaded Executable:** Located at `/Users/Omar.work/Downloads/HRUpdate.exe` (`Size: 4096 bytes`, `MD5: 2d091a73ed45a69d3b66887e7db1e0fd`, `Created: 2025-10-11 19:15:00 EEST`).
* **Prefetch Execution Proof:** Windows Prefetch artifacts **`HRUPDATE.EXE-A1B2C3D4.pf`** (`2025-10-11 19:16:00 EEST`) and **`POWERSHELL.EXE-12AB34CD.pf`** (`2025-10-11 19:20:00 EEST`) provide definitive physical proof that `HRUpdate.exe` executed and subsequently spawned PowerShell.
* **On-Disk Staging Traces:** Upon execution, the stub created `C:\Users\Omar.work\AppData\Roaming\HRApp` containing `activity.log`.

![Malware Executable Metadata](images/03-malware-executable-metadata.png)
![Prefetch Execution Traces](images/04-prefetch-execution-traces.png)

### 3.3 Persistence Mechanism — Scheduled Task (`T1053.005`)
* **Evidence Source:** `/Windows/System32/Tasks/HR/UpdateTask`
* **Findings:** Analysis of the XML task definition (`Author: DESKTOP-327589T\Omar.work`, `Date: 2025-10-11T09:16:00`) revealed a `<LogonTrigger>` configured to automatically execute `C:\Users\Omar.work\Downloads\HRUpdate.exe` every time the user logs onto the workstation.

![Scheduled Task XML Persistence](images/05-scheduled-task-persistence.png)

### 3.4 Credential & Key Compromise (`T1552.001` / `T1552.004`)
* **Compromised SSH Private Key:** Located at `C:\Users\Omar.work\.ssh\id_rsa` (`Size: 259 bytes`), alongside `known_hosts` pointing directly to Bazaarjo's internal source control server (`scm.bazaarjo.com`).
* **Plaintext Git Credentials:** Located at `C:\Users\Omar.work\.git-credentials` (`Size: 51 bytes`), exposing plaintext repository authentication (`https://omar:ba-sa-ar-FAKE-12345@scm.bazaarjo.com`).
* **Targeted Business Artifact:** Internal strategic document **`Q4_Planning.docx`** (`Size: 262,144 bytes`) was also accessed inside the user's `Documents` directory.

![Compromised SSH Private Key](images/06-ssh-private-key-compromise.png)
![Plaintext Git Credentials](images/07-git-credentials-plaintext.png)

---

## 4. Root Cause & Immediate Remediation Recommendations

### Root Cause Analysis
The compromise succeeded due to **spear-phishing social engineering** combined with **unrestricted user-directory executable execution** and **insecure storage of developer secrets in plaintext** (unencrypted SSH private keys and `.git-credentials`) on a developer workstation with direct access to `scm.bazaarjo.com`.

### Immediate Security Recommendations
1. **Network-Level Containment (`Perimeter Firewall & DNS`):** Immediately block outbound traffic to malicious hosting IP **`104.28.223.21`** and sinkhole the spoofed domain **`bazaarjo-careers.com`** across all corporate egress points.
2. **Identity & SCM Credential Rotation (`Zero-Trust Secrets`):** Immediately revoke and rotate Omar's exposed Git credentials and `id_rsa` SSH key pair on `scm.bazaarjo.com`, audit SCM access logs for unauthorized repository clones/commits, and enforce SSH key passphrases or hardware-backed authentication.
3. **Endpoint Execution Hardening (`AppLocker / WDAC`):** Implement `AppLocker` or Windows Defender Application Control policies to block unauthorized `.exe` and script execution from user-writable directories (`Downloads`, `%AppData%`, `%Temp%`).
