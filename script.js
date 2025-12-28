
// === Quiz Data ===
const quizData = [
  // set 1
 {
    question: "Which of the following is NOT a goal of network security?",
    options: ["Confidentiality", "Integrity", "Availability", "Redundancy"],
    answer: 3
  },
  {
    question: "Which protocol is used to securely browse the web?",
    options: ["HTTP", "FTP", "HTTPS", "SMTP"],
    answer: 2
  },
  {
    question: "What is the full form of SSL?",
    options: ["Secure Socket Layer", "Secure System Login", "System Security Layer", "Secure Software Login"],
    answer: 0
  },
  {
    question: "Which of the following is a symmetric encryption algorithm?",
    options: ["RSA", "DES", "ECC", "DSA"],
    answer: 1
  },
  {
    question: "A firewall operates primarily at which OSI layer?",
    options: ["Application", "Transport", "Network", "Data Link"],
    answer: 2
  },
  {
    question: "Which attack involves intercepting and altering communication between two parties?",
    options: ["Phishing", "DoS", "Man-in-the-middle", "Spoofing"],
    answer: 2
  },
  {
    question: "Which of the following is used to detect unauthorized access?",
    options: ["IDS", "IPS", "VPN", "NAT"],
    answer: 0
  },
  {
    question: "Which key is used in asymmetric encryption to decrypt data?",
    options: ["Private key", "Public key", "Session key", "Shared key"],
    answer: 0
  },
  {
    question: "What does the term ‘phishing’ refer to?",
    options: [
      "A type of firewall",
      "A method to steal sensitive information via fake emails",
      "A virus",
      "A type of encryption"
    ],
    answer: 1
  },
  {
    question: "Which of the following is NOT a type of malware?",
    options: ["Worm", "Trojan", "Firewall", "Ransomware"],
    answer: 2
  },
  {
    question: "Which protocol is used for secure file transfer?",
    options: ["FTP", "SFTP", "SMTP", "POP3"],
    answer: 1
  },
  {
    question: "What is the purpose of hashing in security?",
    options: ["To compress data", "To encrypt data", "To verify data integrity", "To hide data"],
    answer: 2
  },
  {
    question: "Which of the following is a denial-of-service attack?",
    options: [
      "Sending large volumes of traffic to crash a server",
      "Stealing passwords",
      "Encrypting files for ransom",
      "Redirecting users to fake websites"
    ],
    answer: 0
  },
  {
    question: "Which of the following is used to create a secure tunnel over the internet?",
    options: ["IDS", "VPN", "NAT", "Proxy"],
    answer: 1
  },
  {
    question: "Which of the following is a public key algorithm?",
    options: ["AES", "DES", "RSA", "Blowfish"],
    answer: 2
  },
  // set 2
  {
    question: "Which of the following is used to ensure data is not altered during transmission?",
    options: ["Encryption", "Hashing", "Compression", "Authentication"],
    answer: 1
  },
  {
    question: "Which of the following is NOT a symmetric key algorithm?",
    options: ["AES", "Blowfish", "RSA", "DES"],
    answer: 2
  },
  {
    question: "What is the main purpose of a digital signature?",
    options: ["Encrypt data", "Verify sender’s identity", "Compress files", "Block malware"],
    answer: 1
  },
  {
    question: "Which of the following is a passive attack?",
    options: ["Eavesdropping", "DoS", "Spoofing", "SQL Injection"],
    answer: 0
  },
  {
    question: "Which layer of the OSI model does SSL operate on?",
    options: ["Application", "Transport", "Session", "Network"],
    answer: 2
  },
  {
    question: "Which of the following is used to prevent replay attacks?",
    options: ["Timestamp", "Firewall", "IDS", "VPN"],
    answer: 0
  },
  {
    question: "Which of the following is a hashing algorithm?",
    options: ["SHA-256", "AES", "RSA", "ECC"],
    answer: 0
  },
  {
    question: "Which of the following is NOT a feature of a firewall?",
    options: ["Packet filtering", "Virus scanning", "NAT", "Proxy services"],
    answer: 1
  },
  {
    question: "Which of the following protocols is used for secure email?",
    options: ["POP3", "SMTP", "S/MIME", "IMAP"],
    answer: 2
  },
  {
    question: "What is the key length of AES-256?",
    options: ["128 bits", "192 bits", "256 bits", "512 bits"],
    answer: 2
  },
  {
    question: "Which of the following is an example of social engineering?",
    options: ["Brute force attack", "Phishing", "Port scanning", "Packet sniffing"],
    answer: 1
  },
  {
    question: "Which of the following is used to detect and block threats in real-time?",
    options: ["IDS", "IPS", "VPN", "Proxy"],
    answer: 1
  },
  {
    question: "Which of the following is a public key cryptography standard?",
    options: ["PKCS", "DES", "RC4", "MD5"],
    answer: 0
  },
  {
    question: "Which of the following is a type of ransomware?",
    options: ["WannaCry", "Zeus", "Stuxnet", "Conficker"],
    answer: 0
  },
  {
    question: "Which of the following protocols provides secure remote login?",
    options: ["Telnet", "SSH", "FTP", "SNMP"],
    answer: 1
  },
// set 3
 {
    question: "Which of the following is used to convert plaintext into ciphertext?",
    options: ["Decryption", "Hashing", "Encryption", "Compression"],
    answer: 2
  },
  {
    question: "Which of the following is NOT a characteristic of a strong password?",
    options: [
      "Includes uppercase and lowercase letters",
      "Contains personal information",
      "Uses special characters",
      "Is at least 8 characters long"
    ],
    answer: 1
  },
  {
    question: "Which of the following is a type of brute-force attack?",
    options: ["Dictionary attack", "Phishing", "Spoofing", "Sniffing"],
    answer: 0
  },
  {
    question: "Which of the following protocols is used to encrypt email messages?",
    options: ["IMAP", "POP3", "S/MIME", "HTTP"],
    answer: 2
  },
  {
    question: "Which of the following is a form of biometric authentication?",
    options: ["Password", "OTP", "Fingerprint", "CAPTCHA"],
    answer: 2
  },
  {
    question: "Which of the following is used to hide the internal IP address of a network?",
    options: ["VPN", "NAT", "IDS", "SSL"],
    answer: 1
  },
  {
    question: "Which of the following is a common port used by HTTPS?",
    options: ["20", "21", "80", "443"],
    answer: 3
  },
  {
    question: "Which of the following is a vulnerability scanner?",
    options: ["Wireshark", "Nmap", "Nessus", "Metasploit"],
    answer: 2
  },
  {
    question: "Which of the following is used to prevent unauthorized access to or from a private network?",
    options: ["Firewall", "Router", "Switch", "Hub"],
    answer: 0
  },
  {
    question: "Which of the following is a secure protocol for remote login?",
    options: ["Telnet", "SSH", "FTP", "HTTP"],
    answer: 1
  },
  {
    question: "Which of the following is a type of logic bomb?",
    options: [
      "Malware that activates on a specific date",
      "Malware that spreads via USB",
      "Malware that encrypts files",
      "Malware that steals passwords"
    ],
    answer: 0
  },
  {
    question: "Which of the following is used to ensure message authenticity and integrity?",
    options: ["Digital Signature", "VPN", "Firewall", "Proxy"],
    answer: 0
  },
  {
    question: "Which of the following is a common hashing algorithm?",
    options: ["AES", "RSA", "SHA-1", "ECC"],
    answer: 2
  },
  {
    question: "Which of the following is an example of a Trojan horse?",
    options: [
      "A program that appears useful but performs malicious actions",
      "A self-replicating program",
      "A program that encrypts files for ransom",
      "A program that floods a network"
    ],
    answer: 0
  },
  {
    question: "Which of the following is used to detect and respond to security incidents?",
    options: ["SIEM", "NAT", "DNS", "DHCP"],
    answer: 0
  },

// set 4

 {
    question: "Which of the following is a common tool for network packet analysis?",
    options: ["Nessus", "Wireshark", "Nmap", "Metasploit"],
    answer: 1
  },
  {
    question: "Which of the following is NOT a type of firewall?",
    options: ["Packet-filtering", "Stateful inspection", "Proxy", "Keylogger"],
    answer: 3
  },
  {
    question: "Which of the following is used to encrypt data in transit?",
    options: ["SSL/TLS", "MD5", "SHA-1", "NAT"],
    answer: 0
  },
  {
    question: "Which of the following is a type of phishing attack that targets executives?",
    options: ["Spear phishing", "Whaling", "Vishing", "Smishing"],
    answer: 1
  },
  {
    question: "Which of the following is a method of hiding data within another file?",
    options: ["Cryptography", "Steganography", "Hashing", "Encoding"],
    answer: 1
  },
  {
    question: "Which of the following is a protocol used for secure shell access?",
    options: ["FTP", "SSH", "Telnet", "RDP"],
    answer: 1
  },
  {
    question: "Which of the following is used to prevent data loss?",
    options: ["IDS", "DLP", "VPN", "NAT"],
    answer: 1
  },
  {
    question: "Which of the following is a symmetric encryption algorithm?",
    options: ["RSA", "ECC", "Blowfish", "DSA"],
    answer: 2
  },
  {
    question: "What is the main purpose of a honeypot in network security?",
    options: ["Encrypt data", "Attract and analyze attackers", "Speed up network traffic", "Block spam"],
    answer: 1
  },
  {
    question: "Which of the following is a secure alternative to Telnet?",
    options: ["FTP", "SSH", "HTTP", "SNMP"],
    answer: 1
  },
  {
    question: "Which of the following is NOT a valid hashing algorithm?",
    options: ["SHA-256", "MD5", "AES", "SHA-1"],
    answer: 2
  },
  {
    question: "Which of the following is a technique used to gain unauthorized access by pretending to be a trusted entity?",
    options: ["Spoofing", "Sniffing", "Scanning", "Flooding"],
    answer: 0
  },
  {
    question: "Which of the following is used to ensure non-repudiation?",
    options: ["Firewall", "Digital Signature", "VPN", "Proxy"],
    answer: 1
  },
  {
    question: "Which of the following is a type of malware that replicates itself?",
    options: ["Trojan", "Worm", "Rootkit", "Spyware"],
    answer: 1
  },
  {
    question: "Which of the following is a protocol used for secure web browsing?",
    options: ["HTTP", "FTP", "HTTPS", "SMTP"],
    answer: 2
  },
// set 5

{
    question: "Which of the following is a type of access control model?",
    options: ["MAC", "TCP", "UDP", "IP"],
    answer: 0
  },
  {
    question: "Which of the following is used to verify the integrity of a message?",
    options: ["Hash function", "Encryption", "Compression", "Firewall"],
    answer: 0
  },
  {
    question: "Which of the following is a vulnerability in web applications?",
    options: ["SQL Injection", "VPN", "SSL", "NAT"],
    answer: 0
  },
  {
    question: "Which of the following is a secure protocol for file transfer?",
    options: ["FTP", "TFTP", "SFTP", "HTTP"],
    answer: 2
  },
  {
    question: "Which of the following is NOT a type of cyber attack?",
    options: ["Phishing", "Spoofing", "Debugging", "Sniffing"],
    answer: 2
  },
  {
    question: "Which of the following is used to encrypt and decrypt messages in asymmetric encryption?",
    options: ["Same key", "Private and public key pair", "Hash function", "OTP"],
    answer: 1
  },
  {
    question: "Which of the following is a tool used for penetration testing?",
    options: ["Metasploit", "Wireshark", "Nessus", "Nmap"],
    answer: 0
  },
  {
    question: "Which of the following is a type of malware that disguises itself as legitimate software?",
    options: ["Worm", "Trojan", "Ransomware", "Spyware"],
    answer: 1
  },
  {
    question: "Which of the following is a technique to prevent unauthorized data access?",
    options: ["Encryption", "Compression", "Fragmentation", "Broadcasting"],
    answer: 0
  },
  {
    question: "Which of the following is a common port number for FTP?",
    options: ["21", "22", "23", "25"],
    answer: 0
  },
  {
    question: "Which of the following is used to detect anomalies in network traffic?",
    options: ["IDS", "NAT", "DHCP", "DNS"],
    answer: 0
  },
  {
    question: "Which of the following is a secure method of authentication?",
    options: ["Username only", "Password only", "Two-factor authentication", "CAPTCHA"],
    answer: 2
  },
  {
    question: "Which of the following is a type of symmetric encryption algorithm?",
    options: ["RSA", "ECC", "AES", "DSA"],
    answer: 2
  },
  {
    question: "Which of the following is a common method used in social engineering?",
    options: ["Port scanning", "Phishing emails", "Packet sniffing", "Firewall bypass"],
    answer: 1
  },
  {
    question: "Which of the following protocols is used to resolve domain names to IP addresses?",
    options: ["DHCP", "FTP", "DNS", "HTTP"],
    answer: 2
  },
// set 6
{
    question: "Which of the following is used to prevent unauthorized wireless access?",
    options: ["WEP", "WPA2", "FTP", "SSL"],
    answer: 1
  },
  {
    question: "Which of the following is a type of biometric security?",
    options: ["Password", "Retina scan", "OTP", "CAPTCHA"],
    answer: 1
  },
  {
    question: "Which of the following is a secure protocol for remote desktop access?",
    options: ["RDP", "FTP", "Telnet", "HTTP"],
    answer: 0
  },
  {
    question: "Which of the following is a method of attack that floods a network with traffic?",
    options: ["DoS", "Spoofing", "Sniffing", "Phishing"],
    answer: 0
  },
  {
    question: "Which of the following is used to convert a domain name into an IP address?",
    options: ["DHCP", "DNS", "FTP", "SSH"],
    answer: 1
  },
  {
    question: "Which of the following is a secure email protocol that uses encryption?",
    options: ["SMTP", "POP3", "IMAP", "PGP"],
    answer: 3
  },
  {
    question: "Which of the following is a type of malware that demands payment?",
    options: ["Worm", "Trojan", "Ransomware", "Spyware"],
    answer: 2
  },
  {
    question: "Which of the following is a common port number for SSH?",
    options: ["21", "22", "23", "25"],
    answer: 1
  },
  {
    question: "Which of the following is used to monitor and analyze network traffic?",
    options: ["IDS", "VPN", "NAT", "DHCP"],
    answer: 0
  },
  {
    question: "Which of the following is a technique used to bypass security mechanisms?",
    options: ["Social engineering", "Encryption", "Authentication", "Hashing"],
    answer: 0
  },
  {
    question: "Which of the following is a secure method for storing passwords?",
    options: ["Plaintext", "Base64 encoding", "Hashing with salt", "Compression"],
    answer: 2
  },
  {
    question: "Which of the following is a type of asymmetric encryption?",
    options: ["AES", "DES", "RSA", "Blowfish"],
    answer: 2
  },
  {
    question: "Which of the following is used to detect and prevent intrusions in real-time?",
    options: ["IDS", "IPS", "NAT", "DNS"],
    answer: 1
  },
  {
    question: "Which of the following is a tool used for ethical hacking?",
    options: ["Metasploit", "Wireshark", "Nessus", "All of the above"],
    answer: 3
  },
  {
    question: "Which of the following is a method to ensure data confidentiality?",
    options: ["Hashing", "Encryption", "Compression", "Fragmentation"],
    answer: 1
  },

// set 7
{
    question: "Which of the following is used to secure wireless networks?",
    options: ["WPA3", "FTP", "Telnet", "HTTP"],
    answer: 0
  },
  {
    question: "Which of the following is a technique to prevent brute-force attacks?",
    options: ["CAPTCHA", "Port forwarding", "NAT", "DNS"],
    answer: 0
  },
  {
    question: "Which of the following is a type of attack that tricks users into clicking malicious links?",
    options: ["Clickjacking", "Spoofing", "Sniffing", "DDoS"],
    answer: 0
  },
  {
    question: "Which of the following protocols is used for secure voice communication over IP?",
    options: ["VoIP", "SRTP", "SIP", "RTP"],
    answer: 1
  },
  {
    question: "Which of the following is used to manage digital certificates?",
    options: ["Certificate Authority (CA)", "DNS", "DHCP", "NAT"],
    answer: 0
  },
  {
    question: "Which of the following is a method of verifying user identity?",
    options: ["Authentication", "Authorization", "Accounting", "Auditing"],
    answer: 0
  },
  {
    question: "Which of the following is a type of attack that overwhelms a system with traffic from multiple sources?",
    options: ["DoS", "DDoS", "MITM", "SQL Injection"],
    answer: 1
  },
  {
    question: "Which of the following is a secure way to store passwords in a database?",
    options: ["Plaintext", "Base64", "Hashed with salt", "Encrypted with symmetric key only"],
    answer: 2
  },
  {
    question: "Which of the following is a tool used to scan open ports on a network?",
    options: ["Nmap", "Wireshark", "Metasploit", "Burp Suite"],
    answer: 0
  },
  {
    question: "Which of the following ensures that a message has not been altered in transit?",
    options: ["Hashing", "Encryption", "Compression", "Encoding"],
    answer: 0
  },
// set 8 
 {
    question: "Which of the following protocols is used to securely access a remote computer?",
    options: ["FTP", "Telnet", "SSH", "HTTP"],
    answer: 2
  },
  {
    question: "Which of the following is a method to ensure availability in network security?",
    options: ["Load balancing", "Encryption", "Authentication", "Hashing"],
    answer: 0
  },
  {
    question: "Which of the following is a common method for attackers to gain access to a system?",
    options: ["Social engineering", "Firewall", "VPN", "NAT"],
    answer: 0
  },
  {
    question: "Which of the following is NOT a goal of the CIA triad?",
    options: ["Confidentiality", "Integrity", "Authentication", "Availability"],
    answer: 2
  },
  {
    question: "Which of the following is used to detect vulnerabilities in a system?",
    options: ["Firewall", "Vulnerability scanner", "IDS", "VPN"],
    answer: 1
  },
  {
    question: "What is the primary function of a proxy server?",
    options: [
      "Encrypt data",
      "Block malware",
      "Act as an intermediary between client and server",
      "Store passwords"
    ],
    answer: 2
  },
  {
    question: "Which of the following is a secure method of communication over an insecure network?",
    options: ["Telnet", "FTP", "HTTPS", "HTTP"],
    answer: 2
  },
  {
    question: "Which of the following is a type of malware that records keystrokes?",
    options: ["Worm", "Keylogger", "Trojan", "Rootkit"],
    answer: 1
  },
  {
    question: "Which of the following is used to prevent unauthorized access to a network?",
    options: ["IDS", "Firewall", "NAT", "DNS"],
    answer: 1
  },
  {
    question: "Which of the following is a type of attack that exploits human psychology?",
    options: ["Brute force", "Phishing", "SQL Injection", "Port scanning"],
    answer: 1
  },
  {
    question: "Which of the following is a secure protocol for transferring files over SSH?",
    options: ["FTP", "SFTP", "TFTP", "HTTP"],
    answer: 1
  },
  {
    question: "Which of the following is used to ensure data integrity?",
    options: ["Encryption", "Hashing", "Compression", "Authentication"],
    answer: 1
  },
  {
    question: "Which of the following is a type of asymmetric encryption algorithm?",
    options: ["AES", "DES", "RSA", "Blowfish"],
    answer: 2
  },
  {
    question: "Which of the following is used to prevent unauthorized data exfiltration?",
    options: ["DLP", "IDS", "NAT", "VPN"],
    answer: 0
  },
  {
    question: "Which of the following is a tool used to analyze network traffic in real-time?",
    options: ["Nmap", "Wireshark", "Metasploit", "Burp Suite"],
    answer: 1
  },
  // set 9
   {
    question: "Which of the following is a common method to secure APIs?",
    options: ["CAPTCHA", "API Gateway", "NAT", "Port Forwarding"],
    answer: 1
  },
  {
    question: "Which of the following best describes a zero-day vulnerability?",
    options: [
      "A known bug with a patch",
      "A vulnerability discovered after a patch is released",
      "A vulnerability unknown to the vendor",
      "A virus that activates after 24 hours"
    ],
    answer: 2
  },
  {
    question: "Which of the following is a secure alternative to HTTP?",
    options: ["FTP", "HTTPS", "Telnet", "SMTP"],
    answer: 1
  },
  {
    question: "Which of the following is used to prevent session hijacking?",
    options: ["Strong passwords", "Session tokens", "Port scanning", "VPN"],
    answer: 1
  },
  {
    question: "Which of the following is a type of attack that manipulates a website’s database?",
    options: ["Phishing", "SQL Injection", "DDoS", "Spoofing"],
    answer: 1
  },
  {
    question: "Which of the following is a key component of Public Key Infrastructure (PKI)?",
    options: ["IDS", "Certificate Authority", "Firewall", "Proxy"],
    answer: 1
  },
  {
    question: "Which of the following is used to ensure that a user is who they claim to be?",
    options: ["Authorization", "Authentication", "Accounting", "Auditing"],
    answer: 1
  },
  {
    question: "Which of the following is a secure protocol for sending emails?",
    options: ["SMTP", "POP3", "IMAP", "SMTPS"],
    answer: 3
  },
  {
    question: "Which of the following is a type of malware that hides its presence?",
    options: ["Worm", "Rootkit", "Ransomware", "Keylogger"],
    answer: 1
  },
  {
    question: "Which of the following is used to encrypt web traffic?",
    options: ["SSL/TLS", "FTP", "HTTP", "Telnet"],
    answer: 0
  },
  {
    question: "Which of the following is a method to prevent data leakage?",
    options: ["NAT", "DLP", "DNS", "DHCP"],
    answer: 1
  },
  {
    question: "Which of the following is a type of social engineering attack?",
    options: ["Brute force", "Phishing", "Port scanning", "SQL Injection"],
    answer: 1
  },
  {
    question: "Which of the following is a standard for wireless network security?",
    options: ["WPA2", "SSL", "FTP", "SSH"],
    answer: 0
  },
  {
    question: "Which of the following is used to verify the identity of a website?",
    options: ["Digital Certificate", "Firewall", "VPN", "IDS"],
    answer: 0
  },
  {
    question: "Which of the following is a tool used to test web application security?",
    options: ["Burp Suite", "Wireshark", "Nmap", "Nessus"],
    answer: 0
  },
// set 10 
 {
    question: "Which of the following is used to prevent unauthorized physical access to a server room?",
    options: ["Firewall", "Biometric scanner", "VPN", "IDS"],
    answer: 1
  },
  {
    question: "Which of the following is a technique used to test system security by simulating an attack?",
    options: ["Penetration testing", "Packet sniffing", "Port forwarding", "NAT"],
    answer: 0
  },
  {
    question: "Which of the following protocols is used to securely synchronize time across systems?",
    options: ["NTP", "SNMP", "FTP", "HTTP"],
    answer: 0
  },
  {
    question: "Which of the following is a method to protect data at rest?",
    options: ["VPN", "Encryption", "Firewall", "IDS"],
    answer: 1
  },
  {
    question: "Which of the following is a tool used to intercept and modify web traffic?",
    options: ["Burp Suite", "Nmap", "Nessus", "Wireshark"],
    answer: 0
  },
  {
    question: "Which of the following is a type of attack that targets the DNS system?",
    options: ["DNS spoofing", "SQL injection", "Phishing", "Brute force"],
    answer: 0
  },
  {
    question: "Which of the following is used to manage user permissions and access rights?",
    options: ["Access Control List (ACL)", "NAT", "VPN", "IDS"],
    answer: 0
  },
  {
    question: "Which of the following is a secure protocol for directory services?",
    options: ["LDAP", "LDAPS", "HTTP", "FTP"],
    answer: 1
  },
  {
    question: "Which of the following is a method to ensure accountability in network security?",
    options: ["Authorization", "Authentication", "Accounting", "Auditing"],
    answer: 3
  },
  {
    question: "Which of the following is a type of malware that provides unauthorized access to a system?",
    options: ["Rootkit", "Worm", "Ransomware", "Spyware"],
    answer: 0
  },
  {
    question: "Which of the following is used to isolate a network from external threats?",
    options: ["DMZ", "IDS", "DHCP", "DNS"],
    answer: 0
  },
  {
    question: "Which of the following is a method to verify the integrity of downloaded files?",
    options: ["Hash comparison", "Compression", "Encryption", "Authentication"],
    answer: 0
  },
  {
    question: "Which of the following is a protocol used for secure communication over a VPN?",
    options: ["PPTP", "L2TP", "IPsec", "FTP"],
    answer: 2
  },
  {
    question: "Which of the following is a common method to prevent email spoofing?",
    options: ["SPF", "DNS", "NAT", "DHCP"],
    answer: 0
  },
  {
    question: "Which of the following is a standard for encrypting web communications?",
    options: ["HTTPS", "FTP", "SMTP", "SNMP"],
    answer: 0
  },
  // set 11
   {
    question: "Which of the following is used to detect unauthorized changes to files?",
    options: ["IDS", "File Integrity Monitoring (FIM)", "VPN", "NAT"],
    answer: 1
  },
  {
    question: "Which of the following is a protocol used to securely browse websites?",
    options: ["HTTP", "FTP", "HTTPS", "SMTP"],
    answer: 2
  },
  {
    question: "Which of the following is a method to prevent tailgating in physical security?",
    options: ["Biometric scanner", "Security camera", "Mantrap", "Firewall"],
    answer: 2
  },
  {
    question: "Which of the following is a type of attack that intercepts communication between two parties?",
    options: ["MITM", "DDoS", "Phishing", "Spoofing"],
    answer: 0
  },
  {
    question: "Which of the following is used to encrypt data on mobile devices?",
    options: ["SSL", "VPN", "Mobile Device Encryption", "IDS"],
    answer: 2
  },
  {
    question: "Which of the following is a standard for secure wireless communication?",
    options: ["WEP", "WPA", "WPA3", "SSL"],
    answer: 2
  },
  {
    question: "Which of the following is a method to ensure secure password storage?",
    options: ["Store in plaintext", "Encrypt with symmetric key", "Hash with salt", "Encode with Base64"],
    answer: 2
  },
  {
    question: "Which of the following is a tool used to automate vulnerability scanning?",
    options: ["Nmap", "Nessus", "Wireshark", "Telnet"],
    answer: 1
  },
  {
    question: "Which of the following is used to prevent unauthorized software installation?",
    options: ["Firewall", "Application Whitelisting", "IDS", "VPN"],
    answer: 1
  },
  {
    question: "Which of the following is a method to ensure secure remote access?",
    options: ["Telnet", "SSH", "HTTP", "FTP"],
    answer: 1
  },
  {
    question: "Which of the following is a type of malware that replicates and spreads without user interaction?",
    options: ["Trojan", "Worm", "Spyware", "Rootkit"],
    answer: 1
  },
  {
    question: "Which of the following is a method to prevent data interception during transmission?",
    options: ["Compression", "Encryption", "Hashing", "Fragmentation"],
    answer: 1
  },
  {
    question: "Which of the following is used to monitor and log user activity?",
    options: ["IDS", "SIEM", "NAT", "VPN"],
    answer: 1
  },
  {
    question: "Which of the following is a type of attack that uses fake websites to steal credentials?",
    options: ["Phishing", "Spoofing", "Sniffing", "Brute force"],
    answer: 0
  },
  {
    question: "Which of the following is a protocol used to manage network devices securely?",
    options: ["SNMPv1", "SNMPv2", "SNMPv3", "SMTP"],
    answer: 2
  },

  // set 12 
   {
    question: "Which of the following is used to prevent unauthorized access to sensitive data on lost or stolen devices?",
    options: ["VPN", "Full Disk Encryption", "Firewall", "IDS"],
    answer: 1
  },
  {
    question: "Which of the following is a method to verify the source of a software update?",
    options: ["Digital Signature", "Firewall", "NAT", "VPN"],
    answer: 0
  },
  {
    question: "Which of the following is a type of attack that involves injecting malicious code into a website?",
    options: ["SQL Injection", "Cross-Site Scripting (XSS)", "Phishing", "Spoofing"],
    answer: 1
  },
  {
    question: "Which of the following is a secure protocol for accessing email over the internet?",
    options: ["IMAP", "POP3", "SMTP", "IMAPS"],
    answer: 3
  },
  {
    question: "Which of the following is used to detect and respond to threats using machine learning and analytics?",
    options: ["SIEM", "IDS", "IPS", "EDR"],
    answer: 3
  },
  {
    question: "Which of the following is a method to ensure that data is only accessible to authorized users?",
    options: ["Confidentiality", "Integrity", "Availability", "Redundancy"],
    answer: 0
  },
  {
    question: "Which of the following is a type of phishing conducted via SMS messages?",
    options: ["Vishing", "Whaling", "Smishing", "Pharming"],
    answer: 2
  },
  {
    question: "Which of the following is a common technique used in password cracking?",
    options: ["Brute force attack", "Packet filtering", "NAT traversal", "Port knocking"],
    answer: 0
  },
  {
    question: "Which of the following is used to isolate applications in a secure environment?",
    options: ["Virtual Machine", "Containerization", "Firewall", "Proxy"],
    answer: 1
  },
  {
    question: "Which of the following is a protocol used to securely manage network devices?",
    options: ["SNMPv1", "SNMPv2", "SNMPv3", "SMTP"],
    answer: 2
  },
  {
    question: "Which of the following is a method to prevent unauthorized USB device usage?",
    options: ["Port scanning", "Device control software", "NAT", "VPN"],
    answer: 1
  },
  {
    question: "Which of the following is a type of malware that locks files and demands payment?",
    options: ["Spyware", "Worm", "Ransomware", "Rootkit"],
    answer: 2
  },
  {
    question: "Which of the following is a method to ensure high availability of services?",
    options: ["Load balancing", "Hashing", "Encryption", "Packet filtering"],
    answer: 0
  },
  {
    question: "Which of the following is used to prevent unauthorized access to a wireless network?",
    options: ["WEP", "WPA", "WPA2", "WPA3"],
    answer: 3
  },
  {
    question: "Which of the following is a tool used to simulate cyberattacks for training purposes?",
    options: ["Red Team toolkit", "IDS", "VPN", "SIEM"],
    answer: 0
  },
  // set 13 
   {
    question: "Which of the following is used to prevent replay attacks in secure communications?",
    options: ["Firewall", "Timestamp and nonce", "NAT", "VPN"],
    answer: 1
  },
  {
    question: "Which of the following is a method to ensure secure software development?",
    options: ["DevOps", "SDLC", "Secure coding practices", "Agile"],
    answer: 2
  },
  {
    question: "Which of the following is a type of attack that floods a network with ICMP Echo Requests?",
    options: ["Smurf attack", "SYN flood", "DNS spoofing", "MITM"],
    answer: 0
  },
  {
    question: "Which of the following is used to detect anomalies in network behavior?",
    options: ["Firewall", "Anomaly-based IDS", "NAT", "VPN"],
    answer: 1
  },
  {
    question: "Which of the following is a method to prevent SQL injection attacks?",
    options: ["Input validation", "Port filtering", "DNSSEC", "NAT"],
    answer: 0
  },
  {
    question: "Which of the following is a secure way to manage multiple user credentials?",
    options: ["Password reuse", "Sticky notes", "Password manager", "Shared spreadsheets"],
    answer: 2
  },
  {
    question: "Which of the following is a type of malware that disguises itself as legitimate software?",
    options: ["Worm", "Trojan", "Ransomware", "Rootkit"],
    answer: 1
  },
  {
    question: "Which of the following is a method to ensure data is not altered during transmission?",
    options: ["Hashing", "Compression", "Encoding", "Fragmentation"],
    answer: 0
  },
  {
    question: "Which of the following is a protocol used to securely transfer files over the internet?",
    options: ["FTP", "TFTP", "SFTP", "HTTP"],
    answer: 2
  },
  {
    question: "Which of the following is used to prevent brute-force login attempts?",
    options: ["CAPTCHA", "NAT", "DNS", "Port forwarding"],
    answer: 0
  },
  {
    question: "Which of the following is a method to ensure only authorized applications run on a system?",
    options: ["Blacklisting", "Whitelisting", "IDS", "VPN"],
    answer: 1
  },
  {
    question: "Which of the following is a type of attack that tricks DNS servers into returning incorrect IP addresses?",
    options: ["DNS poisoning", "Phishing", "MITM", "Smishing"],
    answer: 0
  },
  {
    question: "Which of the following is a secure method for remote desktop access?",
    options: ["Telnet", "RDP with MFA", "FTP", "HTTP"],
    answer: 1
  },
  {
    question: "Which of the following is a method to ensure system availability during failures?",
    options: ["Load balancing", "Encryption", "Hashing", "VPN"],
    answer: 0
  },
  {
    question: "Which of the following is a tool used to test password strength and policy compliance?",
    options: ["John the Ripper", "Wireshark", "Nmap", "Nessus"],
    answer: 0
  },
  // set 14
  {
    question: "Which of the following is a method to prevent unauthorized access to a network via rogue devices?",
    options: ["Port forwarding", "MAC address filtering", "NAT", "DNSSEC"],
    answer: 1
  },
  {
    question: "Which of the following is a type of attack that overwhelms a system with traffic to make it unavailable?",
    options: ["MITM", "DDoS", "Phishing", "Spoofing"],
    answer: 1
  },
  {
    question: "Which of the following is used to ensure that a message has not been tampered with?",
    options: ["Hash function", "Compression", "Encoding", "VPN"],
    answer: 0
  },
  {
    question: "Which of the following is a method to securely erase data from a hard drive?",
    options: ["Formatting", "File deletion", "Data wiping", "Compression"],
    answer: 2
  },
  {
    question: "Which of the following is a type of firewall that filters traffic based on application-level data?",
    options: ["Packet-filtering firewall", "Stateful firewall", "Proxy firewall", "Circuit-level gateway"],
    answer: 2
  },
  {
    question: "Which of the following is used to secure communication between email servers?",
    options: ["HTTPS", "SMTPS", "FTP", "SNMP"],
    answer: 1
  },
  {
    question: "Which of the following is a method to prevent users from visiting malicious websites?",
    options: ["DNS filtering", "NAT", "Port scanning", "VPN"],
    answer: 0
  },
  {
    question: "Which of the following is a type of authentication that uses two or more factors?",
    options: ["Single sign-on", "Multi-factor authentication", "Role-based access control", "Biometrics"],
    answer: 1
  },
  {
    question: "Which of the following is a tool used to analyze and capture network packets?",
    options: ["Wireshark", "Nmap", "Nessus", "Burp Suite"],
    answer: 0
  },
  {
    question: "Which of the following is a method to ensure secure access to cloud services?",
    options: ["VPN", "Cloud Access Security Broker (CASB)", "NAT", "IDS"],
    answer: 1
  }

];

// === DOM Elements ===
const questionEl = document.getElementById("question");
const optionsEl = document.getElementById("options");
const nextBtn = document.getElementById("nextBtn");
const prevBtn = document.getElementById("prevBtn");
const homeBtn = document.getElementById("homeBtn");
const scoreBox = document.getElementById("scoreBox");
const themeToggle = document.getElementById("themeToggle");
const errorMsg = document.getElementById("errorMsg");

// === State ===
let current = parseInt(localStorage.getItem("quizIndex")) || 0;
let score = parseInt(localStorage.getItem("quizScore")) || 0;
let optionSelected = false;

// === Load Question ===
function loadQuestion() {
  const q = quizData[current];
  questionEl.textContent = `Q${current + 1}. ${q.question}`;
  optionsEl.innerHTML = "";
  errorMsg.classList.add("hidden");
  optionSelected = false;

  q.options.forEach((opt, idx) => {
    const li = document.createElement("li");
    li.textContent = opt;
    li.onclick = () => selectOption(li, idx);
    optionsEl.appendChild(li);
  });

  prevBtn.style.display = current > 0 ? "inline-block" : "none";
  nextBtn.style.display = "inline-block";
  homeBtn.classList.add("hidden");
}

// === Select Option ===
function selectOption(selected, idx) {
  const correct = quizData[current].answer;
  const allOptions = document.querySelectorAll("#options li");
  allOptions.forEach((li, i) => {
    li.classList.add(i === correct ? "correct" : "wrong");
    li.onclick = null;
  });

  if (idx === correct) {
    score++;
    playSound("correct");
    fireConfetti();
  } else {
    playSound("wrong");
  }

  optionSelected = true;
  errorMsg.classList.add("hidden");
  localStorage.setItem("quizScore", score);
}

// === Next Button ===
nextBtn.onclick = () => {
  if (!optionSelected) {
    errorMsg.classList.remove("hidden");
    return;
  }

  current++;
  optionSelected = false;

  if (current < quizData.length) {
    localStorage.setItem("quizIndex", current);
    loadQuestion();
  } else {
    showScore();
  }
};

// === Previous Button ===
prevBtn.onclick = () => {
  if (current > 0) {
    current--;
    localStorage.setItem("quizIndex", current);
    loadQuestion();
  }
};

// === Show Score ===
function showScore() {
  questionEl.textContent = "🎉 Quiz Completed!";
  optionsEl.innerHTML = "";
  nextBtn.style.display = "none";
  prevBtn.style.display = "none";
  homeBtn.classList.remove("hidden");
  scoreBox.classList.remove("hidden");
  scoreBox.textContent = `Your Score: ${score} / ${quizData.length}`;
  localStorage.clear();
}

// === Home Button ===
homeBtn.onclick = () => {
  current = 0;
  score = 0;
  optionSelected = false;
  homeBtn.classList.add("hidden");
  scoreBox.classList.add("hidden");
  nextBtn.style.display = "inline-block";
  loadQuestion();
};

// === Theme Toggle ===
themeToggle.onclick = () => {
  document.body.classList.toggle("dark");
  const isDark = document.body.classList.contains("dark");
  themeToggle.textContent = isDark ? "☀️ Light Mode" : "🌙 Dark Mode";
  localStorage.setItem("theme", isDark ? "dark" : "light");
};

// === Load Theme ===
function loadTheme() {
  const saved = localStorage.getItem("theme");
  if (saved === "dark") {
    document.body.classList.add("dark");
    themeToggle.textContent = "☀️ Light Mode";
  }
}

// === Sound Effects ===
function playSound(type) {
  const url = type === "correct"
    ? "mixkit-achievement-bell-600 copy.wav"
    : "error-126627 (1).mp3";
  new Audio(url).play();
}

// === Confetti ===
function fireConfetti() {
  if (typeof confetti === "function") {
    confetti({
      particleCount: 100,
      spread: 70,
      origin: { y: 0.6 }
    });
  }
}

// === Init ===
window.onload = () => {
  loadTheme();
  loadQuestion();
};

// === Load Confetti Library ===
const script = document.createElement("script");
script.src = "https://cdn.jsdelivr.net/npm/canvas-confetti@1.5.1/dist/confetti.browser.min.js";
document.body.appendChild(script);