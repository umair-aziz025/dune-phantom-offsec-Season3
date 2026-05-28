# 📘 WEEK 0 - Tutorial Challenge

<img src="../assets/tutorial.jpg" alt="Week 0 Banner" width="100%">

## Challenge Overview

| Field | Details |
|:------|:--------|
| **Challenge** | Tutorial - Learning the Answer Format |
| **Status** | ✅ 5/5 Completed |
| **Difficulty** | 🟢 Easy |

---

## Objective

Familiarize ourselves with the Gauntlet answer format. Unlike traditional CTF flag submissions, Gauntlet exercises require descriptive text answers with exact identifiers (IPs, filenames, commands, etc.).

## Key Takeaways

1. **Answer formats are flexible** - comma-separated, list format, or prose are all valid.
2. **Accuracy is critical** - missing one required element or adding an extra incorrect one marks the answer as wrong.
3. **No partial feedback** - the grader does not tell you which part is wrong.
4. **Structured lists are recommended** - especially for beginners, they help ensure all components are included.
5. **Never access external resources** - only use the provided lab files.

## Files

| File | Description |
|:-----|:------------|
| `tutorial.txt` | Contains the flag `TryHarder` |
| `access.log` | Web server access log for the final exercise |

## Exercise 5: Web Server Attack Analysis

### Our Approach

We analyzed `access.log` to identify malicious activity:

1. **Filtered for unusual HTTP methods and paths** - found a directory traversal attack pattern.
2. **Identified the attacker IP** - `192.168.1.101` was the only source making path traversal requests.
3. **Traced the exfiltrated file** - the attacker used `../../../../../../../../home/dave/.ssh/id_rsa` via the Grafana plugin path.
4. **Confirmed success** - HTTP 200 response with 1,678 bytes (RSA private key size).

### Answer

```
Source IP Address: 192.168.1.101
Malicious Request: GET /public/plugins/welcome/../../../../../../../../home/dave/.ssh/id_rsa HTTP/1.1
Target File: /home/dave/.ssh/id_rsa
Attack: Directory Traversal (Path Traversal) via Grafana plugin route
Impact: SSH private key exfiltrated - attacker can now SSH as user "dave"
```
