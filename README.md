<div align="center">
  <img src="./assets/dune-phantom-logo.png" alt="Dune Phantom Logo" width="220">
  <h1>Dune Phantom - Gauntlet Season 1 Solutions 🛡️</h1>
  <h3>Ember Expanse · Season 3 · Proving Grounds: The Gauntlet</h3>

  [![Status](https://img.shields.io/badge/Season%201-In%20Progress-00EAFF?style=flat-square)](#)
  [![Challenges](https://img.shields.io/badge/Completed-Week%201-BAFF29?style=flat-square)](#)
  [![Score](https://img.shields.io/badge/Week%201-5%2F5%20Solved-00EAFF?style=flat-square)](#)
</div>

---

Welcome to my solution repository for the **OffSec Dune Phantom** cybersecurity challenge series! This repo contains detailed writeups, investigation reports, and inline analysis code for each weekly challenge from "Proving Grounds: The Gauntlet" event.

---

## About Dune Phantom

> *"The Ember Expanse has always been harsh, but it has never been uncertain. That is changing as a phantom begins stalking the sands with mirage-like cyber attacks that twist what defenders trust most, the truth in their system data."*

<div align="center">
  <video src="./assets/dune-phantom-background-video.webm" width="100%" autoplay loop muted controls></video>
</div>

Dune Phantom is a four-week Gauntlet season where challengers are dropped into escalating defensive lab scenarios. The real fight is separating signal from illusion, validating sources, exposing tampered data, and rebuilding confidence under pressure as the phantom's deception grows sharper each week.

---

## Challenge Solutions

### ✅ [Week 0 - Tutorial Challenge](./WEEK%200%20-%20Tutorial%20Challenge)

<img src="./assets/tutorial.jpg" alt="Week 0 Banner" width="100%">

**Status:** COMPLETED
**Category:** Log Analysis, Path Traversal Detection
**Difficulty:** Easy

**Scenario:** Introduction to Gauntlet answer format. Participants learn how to submit descriptive text answers, then analyze a web server access log to identify a directory traversal attack targeting SSH private keys.

**Key Skills:**
- Web server log analysis
- Path traversal vulnerability identification
- Answer format familiarization

**Key Findings:**
- Identified path traversal attack from IP `192.168.1.101`
- Detected SSH private key exfiltration (`/home/dave/.ssh/id_rsa`)
- Attack achieved HTTP 200 with 1,678 bytes exfiltrated

**Files:**
- [Investigation Report](./WEEK%200%20-%20Tutorial%20Challenge/INVESTIGATION_REPORT.md)

---

### ✅ [Week 1 - First Illusion](./WEEK%201%20-%20First%20Illusion)

<img src="./assets/first-illusion.jpg" alt="Week 1 Banner" width="100%">

**Status:** COMPLETED
**Category:** Cloud Incident Response, AWS Forensics, CI/CD Security
**Difficulty:** Hard

**Scenario:** EduNexus Learning Systems suffered a full cloud account takeover. A threat actor discovered an exposed `.git/config` on a public S3 website, extracted a GitLab Personal Access Token, backdoored a CI/CD pipeline to steal AWS IAM credentials, escalated privileges through a chain of STS AssumeRole calls, then encrypted S3 data using customer-provided encryption keys (SSE-C) and locked out defenders.

**Key Skills:**
- AWS CloudTrail management and S3 data event analysis
- GitLab API and Nginx access log correlation
- EC2 Systems Manager (SSM) agent log forensics
- IAM trust relationship and AssumeRole chain mapping
- S3 Server-Side Encryption (SSE-C) attack detection

**Key Findings:**
- Attacker used `ffuf/2.1.0-dev` to fuzz public S3 website and discover `.git/config`
- Emily Johnson's GitLab PAT (Token ID 2, User ID 12) leaked via exposed config
- Malicious branch `xvduapqweksk` pushed to trigger CI/CD credential theft from IMDSv2
- SSM `SendCommand` used to inject SSH backdoor key (`ghost@finger`) on bastion host
- Five-step IAM escalation: `GitLabRunner` > `bastion` > `Ops_t1` > `Ops_t2` > `DevOps_full`
- S3 data encrypted via `PutObject` with SSE-C (MITRE T1486) across 17 buckets (229 objects)
- Defender lockout via `DeleteAccessKey`/`DeleteLoginProfile` on 4 admin users

**Files:**
- [Investigation Report](./WEEK%201%20-%20First%20Illusion/INVESTIGATION_REPORT.md)
- [Attack Chain Diagram](./WEEK%201%20-%20First%20Illusion/attack_chain_diagram.png)

<img src="./assets/first-illusion-conclusion.jpg" alt="First Illusion Conclusion" width="100%">

### 🔮 The Mirage Begins

> **The Mirage Begins**
> By correlating logs across multiple systems, you were able to track the attacker's steps and uncover what they did, but the method used to encrypt the data is not easily reversible. As the investigation came into focus, one detail stood apart from the rest: a deliberate signature left by the intruder, a message reading, "What you trusted was the first illusion. - Dune Phantom"
> 
> **Beyond the Logs**
> 
> The Dune Phantom is not after ransom alone, but control over what defenders believe. It twists forgotten tokens, trusted automation, impersonated roles, and unquestioned logs into mirages. At EduNexus, the corrupted data was only the visible wound, its real goal is to make truth unreliable and leave defenders doubting their tools, their evidence, and each other.

---

## Tools and Methodology

- **Log Parsing:** Custom Python scripts for programmatic analysis of CloudTrail JSON, Nginx access logs, GitLab Rails API logs, and SSM agent logs
- **Cloud Forensics:** AWS CloudTrail management event and S3 data event correlation
- **Web Application Forensics:** GitLab API request and Nginx access log correlation
- **OS Forensics:** EC2 instance SSM agent log, audit log, and system log review
- **IAM Analysis:** STS AssumeRole chain mapping and IAM trust policy auditing

---

## Repository Structure

```
dune-phantom-gauntlet-Season-3/
├── .gitignore
├── README.md
├── assets/
│   ├── dune-phantom-logo.png
│   ├── dune-phantom-background-video.webm
│   ├── tutorial.jpg
│   ├── first-illusion.jpg
│   └── first-illusion-conclusion.jpg
├── WEEK 0 - Tutorial Challenge/
│   └── INVESTIGATION_REPORT.md
└── WEEK 1 - First Illusion/
    ├── INVESTIGATION_REPORT.md
    └── attack_chain_diagram.png
```
