# Assignment 2 Report
**Course:** CSCI 4742 Cybersecurity Programming and Analytics  
**Name:** Meme Chhay
**Date:** 4/16/2026

---

# Part 1: Advanced Exploitation with Metasploit

## Task 1: UnrealIRCd Backdoor Exploit

### Screenshots
- Nmap Scan showing port 6667 open and UnrealIRCd version
- Metasploit module configuration
- Successful reverse shell (`whoami`, `id`, `uname -a`)

---

### Analysis Questions

1. This backdoor differs from typical vulnerabilities because it is intentionally inserted malicious code, whereas vulnerabilities like buffer overflows are accidental programming errors.

2. It is concerning because users trust open-source software. A compromised distribution can affect many systems without detection.

3. Prevention methods include:
   - File integrity verification (hash/signatures)
   - Secure package repositories
   - Runtime monitoring

4. It violates trust assumptions because network services assume valid input, but here input triggers hidden malicious behavior.

5. Egress filtering would block outbound reverse shell traffic, preventing attacker control.

6. MITRE ATT&CK:
   - Initial Access
   - Execution
   - Command and Control (Reverse Shell)

7. Detection methods:
   - IDS/IPS monitoring unusual traffic
   - Log analysis
   - File integrity monitoring

8. Proper practices:
   - Regular patching
   - Avoid outdated software
   - Verify software sources

9. This demonstrates supply chain risk since compromised software affects all downstream users.

---

## Task 2: Tomcat Manager Exploit

### Screenshots
- Nmap scan showing port 8180
- Successful login using default credentials
- Meterpreter session (`sysinfo`, `getuid`)

---

### Analysis Questions

1. Default credentials are widely known and violate least privilege principles.

2. The Manager interface allows deployment of applications, which can execute arbitrary code.

3. WAR files are standard deployment units in Tomcat, making them ideal for delivering payloads.

4. MITRE ATT&CK:
   - T1190 Exploit Public-Facing Application
   - T1059 Command Execution

5. Post-exploitation actions:
   - Persistence (backdoors)
   - Privilege escalation
   - Lateral movement

6. Defenses may fail because:
   - Traffic appears legitimate (HTTP)
   - No signature-based detection

7. Mitigations:
   - Disable Manager interface
   - Restrict IP access
   - Use MFA
   - Strong authentication

8. Risks of outdated software:
   - Unpatched vulnerabilities
   - Lack of support
   - Compliance violations

---

# Part 2: Memory Corruption in Native C Applications

## Task 1: Stack Protections Comparison

### Screenshots
- Compilation commands
- Overflow execution results
- dmesg logs

---

### Analysis Questions

1. Stack canaries detect memory corruption before function return.

2. Protected version terminates safely because it detects tampering.

3. `-z execstack` allows execution of injected shellcode, increasing exploitability.

4. Shellcode could execute if protections are disabled.

5. Attackers could overwrite return addresses to hijack execution.

6. `dmesg` logs segmentation faults from crashes, while protected program exits cleanly.

---

## Task 2: Static Analysis

### Comparison Table

| Vulnerability | Cppcheck | Flawfinder | CWE | Risk | Notes |
|--------------|---------|------------|-----|------|------|
| strcpy() | Yes | Yes | CWE-120 | High | Unsafe copy |
| atoi() | No | No | N/A | Low | Hard to detect |
| printf(input) | Yes | Yes | CWE-134 | High | Format string |
| Fixed buffer | Yes | Yes | CWE-120 | Medium | Overflow risk |
| Missing includes | No | No | N/A | Low | Not critical |

---

### Analysis Questions

1. Flawfinder detects known unsafe functions; atoi overflow is context-based and harder to flag.

2. Cppcheck has limited ability to detect runtime or logical issues.

3. CWE tags:
   - CWE-120: Buffer overflow
   - CWE-134: Format string vulnerability

4. Manual review identifies context-specific issues tools miss.

5. Additional strategies:
   - Fuzz testing
   - Dynamic analysis
   - Code review

---

## Task 3: Dynamic Analysis

### Comparison Table

| Vulnerability | ASan | UBSan | Valgrind | Notes |
|--------------|------|------|----------|------|
| Buffer Overflow | Yes | No | Yes | Stack corruption detected |
| Integer Overflow | No | Yes | Partial | Undefined behavior |
| Format String | No | No | No | Not detected |

---

### Analysis Questions

1. ASan gives best memory diagnostics; UBSan detects undefined behavior.

2. Format string bugs do not always cause memory violations.

3. ASan detects stack issues better; Valgrind detects heap issues.

4. Using all tools improves coverage.

5. Tools help identify root causes and memory misuse.

---

## Task 4: Secure Refactoring

### Root Causes
- Unsafe functions (`strcpy`, `printf`)
- Lack of bounds checking
- No input validation

---

### Secure Code Practices
- Use `strncpy`
- Validate inputs
- Use safe format functions (`printf("%s", input)`)

---

### protected_code.c Summary
- Input validation added
- Bounds checking implemented
- Secure memory handling used

---

### Compiler Mitigations
- Stack canaries
- Non-executable stack
- Address randomization

---

# Part 3: Web Exploitation with Mutillidae

## Task 1: SQL Injection

### Screenshot
[Insert Screenshot]

### Analysis
- Injection Type: Authentication bypass
- Input field vulnerable due to lack of sanitization

### Mitigation
- Prepared statements
- Input validation

---

## Task 2: Command Injection

### Screenshots
[Insert Multiple Screenshots]

### Analysis
- Injection Type: Command execution
- Can extract system data

### Mitigation
- Input sanitization
- Disable system command execution

---

## Task 3: Cross-Site Scripting

### Screenshots
- Reflected XSS
- Stored XSS

### Analysis
- Injected scripts execute in browser

### Mitigation
- Output encoding
- Content Security Policy

---

# Part 4: Vulnerability Scanning and Analysis

## Task 1: Nmap Scans

### Screenshots
- Full scan
- Vulnerability scan

---

## Task 2: Technical Analysis of 5 Vulnerabilities

| CVE | Port | Service | Description | CVSS |
|-----|------|--------|------------|------|
| CVE-2010-2075 | 6667 | IRC | UnrealIRCd backdoor | High |
| CVE-2009-3843 | 8180 | Tomcat | Default creds exploit | High |
| CVE-XXXX | 21 | FTP | Example | Medium |
| CVE-XXXX | 80 | HTTP | Example | Medium |
| CVE-XXXX | 3306 | MySQL | Example | High |

---

## Task 3: CWE Classification

- CWE-120 Buffer Overflow
- CWE-89 SQL Injection
- CWE-134 Format String
- CWE-78 Command Injection
- CWE-79 XSS

---

## Task 4: ATT&CK Mapping

- Initial Access (T1190)
- Execution (T1059)
- Persistence

---

## Task 5: Mitigation Strategies

| Vulnerability | Technical Control | Administrative Control |
|--------------|------------------|------------------------|
| UnrealIRCd | Patch/update | Software validation |
| Tomcat | Disable manager | Strong password policy |
| SQLi | Input validation | Secure coding training |
| Command Injection | Sanitization | Access control |
| XSS | Output encoding | Security awareness |

---

# Conclusion

This assignment demonstrated exploitation techniques, vulnerability analysis, and mitigation strategies across network, system, and web layers.
