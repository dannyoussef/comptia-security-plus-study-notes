# 3.1 Given a scenario, implement secure protocols.
* **Protocols**
    * **Domain Name System Security Extensions (DNSSEC):** a feature of the DNS that authenticates responses to domain name lookups.
    * **SSH:** the secure shell protocol is a cryptographic network protocol for operating network services securely over an unsecure network.
    * **Secure/Multipurpose Internet Mail Extensions (S/MIME):** for sending digitally signed and encrypted messages.
    * **Secure Real-time Transport Protocol (SRTP):** provides encryption, message authentication and integrity, and replay attack protection to the RTP data.
    * **Lightweight Directory Access Protocol Over SSL (LDAPS):** secure version of LDAP that encrypts the authentication process and uses  TLS/SSL as a transmission protocol.
    * **File Transfer Protocol, Secure (FTPS):** an extension to the FTP that adds support for the TLS and SSL protocols.
    * **SSH File Transfer Protocol (SFTP):** for securely accessing, transferring  and managing large files and sensitive data.
    * **Simple Network Management Protocol, version 3 (SNMPv3):** an internet standard protocol used to monitor and manage network devices connected over an IP and provides security with authentication and privacy.
    * **Hypertext transfer protocol over SSL/TLS (HTTPS):** an extension of the HTTP that uses encryption for secure communication over a computer network.
    * **IPSec**
        * **Authentication header (AH)/Encapsulating Security Payloads (ESP):** AH provides a mechanism for authentication. ESP provides data cofidentiality (encryption) and authentication (data integrity, data origin authentication, and replay protection).
        > AH is faster than ESP because it does not perform encryption. ESP can be used with only with either confidentiality or authentication, or both.
        * **Tunnel/transport:** in tunnel mode, two IP headers are sent; the inner IP packet determines the IPsec policy that protects its content. In transport mode, the IP addresses in the outer header are used to determine the IPsec policy that will be applied to the packet.
        > Transport mode is good for ESP host-to-host traffic.
    * **Post Office Protocol (POP)/Internet Message Access Protocol (IMAP):** POP extracts and retrieves email from a remote email server for access by the host machine. IMAP allows access to email wherever you are, from any device.
* **Use cases**
    * **Voice and video:** SRTP.
    * **Time synchronization:** NTP.
    * **Email and web:** S/MIME, HTTPS, POP/IMAP.
    * **File transfer:** FTPS, SFTP.
    * **Directory services:** LDAPS.
    * **Remote access:** SSH.
    * **Domain name resolution:** DNSSEC.
    * **Routing and switching:** STP.
    * **Network address allocation:** SNMPv3.
    * **Subscription services:** HTTPS, TLS/SSL.
# 3.2 Given a scenario, implement host or application security solutions.
* **Endpoint protection**
    * **Antivirus:** a software program designed to detect and destroy viruses and other malicious software from the system
    * **Anti-malware:** a program that protects the system from all kinds of malware including viruses, Trojans, worms, and potentially unwanted programs (PUPs).
    * **Endpoint detection and response (EDR):** an integrated endpoint security solution that combines real-time continuous monitoring and collection of endpoint data, with rule-based automated response and analysis capabilities.
    * **DLP:** data loss prevention (DLP) is a set of tools and procedures that forms part of a company's overall security strategy and focuses on detecting and preventing the loss, leakage, or misuse of data through breaches, exfiltration transmissions, and unauthorized use.
    * **Next-generation firewall (NGFW):** a part of the third generation of firewall technology, combining a conventional firewall with other network device filtering functions.
    > A deep-packet inspection firewall that moves beyond port/protocol inspection and blocking. Adds application-level inspection, intrusion prevention, and brings intelligence from outside the firewall.
    * **Host-based intrusion prevention systems (HIPS):** analyzes whole packets, both header and payload, looking for known events. When a known event is detected, a log message is rejected.
    * **Host-based intrusion detection system (HIDS):** similar to HIDS, but the packet is rejected when a known event is detected. 
    * **Host-based firewall:** an application firewall that is built into desktop operating systems, like Windows or Linux.
    > Since it is an application, it is more vulnerable to attack in some respects (versus hardware firewalls).
* **Boot integrity:** ensures host is protected during the boot process, so all protections are in place when system is fully operational.
    * **Boot security/Unified Extensible Firmware Interface (UEFI):** a modern version of the Basic Input/Output System (BIOS) that is more secure and is needed for a secure boot of the OS.
    > The older BIOS cannot provide secure boot.
    * **Measured boot:** where all components from the firmware, applications, and software are measured and information stored in a log file.
    > The log file is on the Trusted Platform Module (TPM) chip on the motherboard.
    * **Boot attestation:** a secure mechanism to verify the software integrity.
    > OSs such as Windows 10 can perform a secure boot at startup where the OS checks that all of the drivers have been signed. If they have not, the boot sequence fails as the system integrity has been compromised.
* **Database** 
    * **Tokenization:** takes sensitive data, such as a credit card number, and replaces it withj random data.
    > Deemed more secure than encryption because it cannot be reversed.
    * **Salting:** adding random text before hashing to increase the compute time for a brute-force attack.
    * **Hashing:** used to index and fetch items from a database. Makes the search faster as the hash key is shorter than the data.
    > The hash function maps data to where the actual records are held.
* **Application security**
    * **Input validations:** ensures buffer overflow, integer overflow, and SQL injection attacks cannot be launched against applications and databases.
    > Use where data is entered either using a web page or wizard, only accepting data in the correct format and within a range of minumum and maximum values.
    * **Secure cookies:** used by web browsers and contain information about your session. Can be stolen by attackers to carry out a session hijacking session.
    > Setting the secure flag in website code to ensure that cookies are only downloaded when there is a secure HTTPS session.
    * **Hypertext Transfer Protocol (HTTP) headers:** designed to transfer information between the host and the web server. An attacker can carry out cross-site scripting (XSS) as it is mainly delivered through injecting HTTP response headers.
    > Can be prevented by entering the HTTP Strict Transport Security (HSTS) header, which ensures that the browser will ignore all HTTP connections.
    * **Code signing:** uses a certificate to digitally sign scripts and executables to verify their authenticity and to confirm that they are genuine.
    * **Allow list:** only explicity allowed applications can run. This can be done by setting up an application whitelist.
    > Firewalls, IDS/IPS, and EDR systems can have an allow list.
    * **Block list/deny list:** prevents specificed applications from being installed or run in the specificed security solution.
    > Firewalls, IDS/IPS, and EDR systems can have a block list.
    * **Secure coding practices:** developer who creates software should write code in a manner that ensures that there are no bugs or flaws.
    > Intent is to prevent attacks, such as buffer overflows or integer injections.
    * **Static code analysis:** analysis where the code is not executed locally but is analyzed by a static code analyzer tool.
        * **Manual code review:** the process of reading the source code line by line to look out for possible vulnerabilities.
    * **Dynamic code analysis:** code is executed, and a technique called fuzzing is used to inject random input into the application. The output is reviewed to ensure appropriate handling of unexpected input.
    > Exposes flaws in an application before it is rolled out to production. This method does not require source code access.
    * **Fuzzing:** an automated software testing method that injects invalid, malformed, or unexpected inputs into a system to reveal software defects and vulnerabilities.
* **Hardening**
    * **Open ports and services:** listening ports should be restricted to those necessary, filtered to restrict traffic, and disabled entirely if not needed.
    * **Registry:** access should be restricted, and updates controlled through policy where possible.
    > Always take a backup of the registery before you start making changes.
    * **Disk encryption:** can prevent unwanted access to data.
    * **OS:** can be implemented through security baselines, such as group policies or management tools (like MDM), and the above hardening strategies..
    * **Patch management:** ensures that systems are kept up-to-date with current patches.
        * **Third-party updates:** patching and updating outdated third-party applications.
        * **Auto-update:** automatically updating software and applications.
* **Self-encrypting drive (SED)/full-disk encryption (FDE)** encryption on a SED that's built into the hardware of the drive itself. Anything that's written to that drive is automatically stored in encrypted form. FDE is built into the Windows OS. Bitlocker is an implementation of FDE.
    * **Opal:** the Opal Storage Specification is a set of specifications for features of data storage devices (such as HDDs and SSDs).
    > Defines a way of encrypting the stored data so that an unauthorized person who gains possession of the device cannot see the data.
* **Hardware root of trust:** when certificates are used in FDE, they use a hardware root of trust for key storage.
> It verifies that the keys match before the secure boot process takes place.
* **Trusted Platform Module (TPM):** a chip that resides on the motherboard of the device. Multi-purpose, like storage and management of keys used for FDE solutions.
> Provides the OS with access to keys, but prevents drive removal and data access.
* **Sandboxing:** security practice where you run, observe, and analyze code in a safe, isolated environment on a network that mimics end-user operating environments.
> Also, facilitates investigating dangerous malware.
# 3.3 Given a scenario, implement secure network designs.
* **Load balancing**
    * **Active/active:**
    * **Active/passive:**
    * **Scheduling:**
    * **Virtual IP:**
    * **Persistence:**
* **Network segmentation**
    * **Virtual local area network (VLAN):**
    * **Screened subnet (previously known  as demilitarized zone):**
    * **East-west traffic:**
    * **Extranet:**
    * **Intranet:**
    * **Zero trust:**
* **Virtual private network (VPN)**
    * **Always-on:**
    * **Split tunnel vs. full tunnel:**
    * **Remote access vs. site-to-site:**
    * **IPSec:**
    * **SSL/TLS:**
    * **HTML5:**
    * **Layer 2 tunneling protocol (L2TP):**
* **DNS:**
* **Network access control (NAC)**
    * **Agent and agentless:**
* **Out-of-band management:**
* **Port security**
    * **Broadcast storm prevention:**
    * **Bridge Protocol Data Unit (BPDU) guard:**
    * **Loop prevention:**
    * **Dynamic Host Configuration Protocol (DHCP) snooping:**
    * **Media access control (MAC) filtering:**
* **Network appliances**
    * **Jump servers:**
    * **Proxy servers**
        * **Forward:**
        * **Reverse:**
    * **Network-based intrusion detection system (NIDS)/network-based intrustion prevention system (NIPS)**
        * **Signature-based:**
        * **Heuristic/behavior:**
        * **Anomaly:**
        * **Inline vs. passive:**
    * **HSM:**
    * **Sensors:**
    * **Collectors:**
    * **Aggregators:**
    * **Firewalls**
        * **Web application firewall (WAF):**
        * **NGFW:**
        * **Stateful:**
        * **Stateless:**
        * **Unified threat management (UTM):**
        * **Network address translation (NAT) gateway:**
        * **Content/URL filter:**
        * **Open-source vs. proprietary:**
        * **Hardware vs. software:**
        * **Appliance vs. host-based vs. virtual:**
* **Access control list (ACL):**
* **Route security:**
* **Quality of service (QoS):**
* **Implications of IPv6:**
* **Port spanning/port mirroring**
    * **Port taps:**
* **Monitoring services:**
* **File integrity monitors:**
# 3.4 Given a scenario, install and configure wireless security settings.
# 3.5 Given a scenario, implement secure mobile solutions.
# 3.6 Given a scenario, apply cybersecurity solutions to the cloud.
# 3.7 Given a scenario, implement identity and account management controls.
# 3.8 Given a scenario, implement authentication and authorization solutions.
# 3.9 Given a scenario, implement public key infrastructure.