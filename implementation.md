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
* **Load balancing:** a network load balancer (NLB) is a device that is used to direct traffic to an array of web servers, application servers, or other service endpoints.
    * **Active/active:** the load balancers act like an array, dealing with the traffic together as both are active.
    > A single LB failure may degrade performance.
    * **Active/passive:** the active node is fulfilling load balancing duties and the passive node is listening and monitoring the active node.
    > If the active node fails, the passive node takes over, providing redundancy.
    * **Scheduling:** determines how the load is distributed by the load balancer.
    * **Virtual IP:** eliminates a host's dependency upon individual network interfaces.
    > Web traffic comes into the NLB from the VIP on the front end, and the request is sent to one of the web servers in the server farm (on the backend).
    * **Persistence:** also known as a sticky session, makes it possible for the LB to identify requests coming from the same client and to always send those requests to the same server.
* **Network segmentation**
    * **Virtual local area network (VLAN):** a collection of devices that communicate with one another as if they made up a single physical LAN.
    * **Screened subnet (previously known  as demilitarized zone):** an extranet for public consumption. Serves as the buffer and separates the internal and external areas.
    > A subnet is placed between two routers or firewalls. Used to control traffic and isolate static/sensitive environments.
    * **East-west traffic:** where traffic moves laterally between servers within a data center.
    > North-south traffic moves outside of the data center.
    * **Extranet:** a section of an organization's network that has been sectioned off to act as an intranet for the private network, but also serves information to external business partners or the public Internet.
    * **Intranet:** a private network designed to host the information internal to an organization.
    * **Zero trust:** networks are segmented into smaller islands where specific workloads are contained.
    > Used to minimize the impact of unauthorized access to data.
* **Virtual private network (VPN):** extends a private network across a public network, enabling users and devices to send and receive data across shared or public networks as if their computing devices were directly connected to the private network.
    * **Always-on:** a low-latency point-to-point connection between two sites. A tunnel between two gateways that is "always connected."
    * **Split tunnel vs. full tunnel:** split tunnel uses VPN for traffic destined for the corporate network only, and Internet traffic direct through its normal route. Full tunnel means using VPN for all traffic, both to the Internet and corporate network.
    * **Remote access vs. site-to-site:** with remote access, a connection is initiated from a user's PC or laptop for a connection of shorter duration. With site-to-site, IPSec site-to-site VPN uses an always-on mode where both packet header and payload are encrypted.
    * **IPSec:** adds encryption and authentication to make the Internet Protocol more secure.
    * **SSL/TLS:** works with legacy systems and uses SSL certificates for authentication.
    * **HTML5:** similar to the SSL VPN, it uses certificates for authentication.
    * **Layer 2 tunneling protocol (L2TP):** most secure tunneling protocol that can use certificates, Kerberos authentication, or a pre-shared key.
* **DNS:** a hierarchical naming system that resolves a hostname to an IP address.
* **Network access control (NAC):** a security solution that enforces policy on devices that access networks to increase network visibility and reduce risk.
    * **Agent and agentless:** agent-based NAC requires the installation of a software agent on every device that needs network access. Some OSs include NAC as part of the OS itself, with no additional agent required (agentless).
* **Out-of-band management:** OoB is a concept that uses an alternate communicate path to manage network infrastructure devices.
> Enables IT to work around problems that may be occuring on the network. 
* **Port security:** enables you to configure each switch port with a unique list of the MAC addresses of devices that are authorized to access the network through that port.
    * **Broadcast storm prevention:** a broadcast storm occurs a network is overwhelmed by a large number of broadcast packets. Spanning Tree Protocol (STP) prevents this from happening by forwarding, listening, or blocking some of the ports.
    * **Bridge Protocol Data Unit (BPDU) guard:** BPDUs are frames that contain information about the STP. A BPDU guard enables the STP to stop attacks that attempt to spoof the root bridge so that the STP is recalculated.
    * **Loop prevention:** loop prevention protocols are essential for avoiding network congestion, instability, and performance degradation caused by the formation of loops in a LAN switching environment.
    * **Dynamic Host Configuration Protocol (DHCP) snooping:**
    * **Media access control (MAC) filtering:** a list of authorized wireless client interface MAC addresses. Used by a wireless access point to block access to all non-authorized devices.
* **Network appliances**
    * **Jump servers:** typically placed on a screened subnet, allows admins to connect remotely to the network.
    * **Proxy servers**
        * **Forward:** server that controls requests from clients seeking resources on the internet or an external network.
        * **Reverse:** placed on a screened subnet, performs the authentication and decryption of a secure session to enable it to filter the incoming traffic.
    * **Network-based intrusion detection system (NIDS)/network-based intrustion prevention system (NIPS)**
        * **Signature-based:**
        * **Heuristic/behavior:** creates a baseline of activity to identify normal behavior and then measures system performance against the baseline to detect abnormal behavior.
        * **Anomaly:** similar to behavior-based.
        * **Inline vs. passive:** with inline, NIDS/NIPS placed on or near the firewall as an additional layer of security. With passive, traffic does not go through the NIDS/NIPS.
    * **HSM:** a hardware security module (HSM) is a physical computing device that safeguards and manages digital keys, performs encryption and decryption functions for digital signatures, strong authentication, and other crytographic functions.
    > Like a TPM, but are often removable or external devices.
    * **Sensors:** designed to handle traffic at wire speed and monitor network traffic.
    * **Collectors:** a network appliance for the collection, storage, and analysis of flow data from flow-enabled network devices (LB, switches, and routers).
    * **Aggregators:** cost-effective solutions for the tapping and aggregating of traffic to feed to network monitoring or cybersecurity tools.
    * **Firewalls**
        * **Web application firewall (WAF):** protect web applications by filtering and monitoring HTTP traffic between a web application and the Internet.
        > Typicallys protects again common attacks like XSS, CSRF, and SQL injection.
        * **NGFW:** a "deep-packet inspection" firewall that moves beyond port/protocol inspection and blocking. Adds application-level inspection, intrusion prevention, and brings intelligence from outside the firewall.
        * **Stateful:** can watch traffic streams from end to end. Are aware of communication paths and can implement various IP security functions such as tunnels and encryption.
        > Better at identifying unauthorized and forged communications.
        * **Stateless:** watch network traffic and restrict or block packets based on source and destination addresses or other static values. Not aware of traffic patterns or data flows.
        > Typically faster and performs better under heavier traffic loads.
        * **Unified threat management (UTM):** a multifunction device (MFD) composed of several security features in addition to a firewall. May include IDS, IPS, a TLS/SSL proxy, web filtering, QoS management, bandwidth throttling, NAT, VPN anchoring, and antivirus.
        * **Network address translation (NAT) gateway:** allows private subnets to communicate with other cloud services and the Internet but hides the internal network from Internet users. The NAT gateway has the Network Access Control List (NACL) for the private subnets.
        * **Content/URL filter:** looks at the content on the requested web page and blocks requests depending on filters. Used to block inappropriate content in the context of the situation.
        * **Open-source vs. proprietary:** open-source; the license is freely available and allows access to the source code, though it might ask for an optional donation. No vendor support, so third-party support may be necessary. E.g., pfsense. Proprietary; are more expensive but tend to provide mode/better protection and more functionality and support (at a cost). No source code access. E.g., Cisco, Checkpoint, Palo Alto, Barracuda.
        * **Hardware vs. software:** hardware; purpose-built network hardware. May offer more configurable support for LAN and WAN connections. Often has superior throughput versus software because it is hardware designed for the speeds and connections common to an enterprise network. Software; might install on your own hardware. Provide flexibility to palce firewalls anywhere you'd like in your organization. On servers and workstations, you can run a host-based firewall.
        * **Appliance vs. host-based vs. virtual:** application; typically catered specifically to application communications, that is, HTTP or web traffic. E.g., NGFW. Host-based; an application installed on a host OS, such as Windows or Linux, both client and server OSs. Virtual; in the cloud, firewalls are implemented as virtual network appliances (VNA). Available from both the CSP directly and third-party partners (commercial firewall vendors).
* **Access control list (ACL):** a list used to allow or deny traffic. If no allow rules, last rule (deny) is applied (implicitly).
* **Route security:**
* **Quality of service (QoS):** ensures that applications have the bandwidth they need to operate by prioritizing traffic based on importance and function.
> Traffic of real-time functions (e.g., voice and video streaming) might be given greater priority.
* **Implications of IPv6:** many more IPv6 addresses compared to IPv4. More difficult to perform a complete port scan or interface scan. Less need to perform port address translation (PAT) or outbound network address translation (NAT) on the network. The Address Resolution Protocol (ARP) is removed.
> Does not imply IPv6 is more or less secure, but changes the attack vectors.
* **Port spanning/port mirroring:** sends a copy of all data that arrives at a port to another device or sensor for investigation later or in near real-time.
    * **Port taps:** a dedicated hardware device, which provides a way to access the data flowing across a computer network.
* **Monitoring services:** often an outsourced security operations center (SOC) function to provide 24x7 monitoring and alert or remediate issues after business hours.
* **File integrity monitors:** monitors and detects changes to files that should not be modified automating notification (and potentially remediation).
> Commonly monitors files that would never change things like your OS files, where changes indicate some type of malicious activity.
# 3.4 Given a scenario, install and configure wireless security settings.
* **Cryptographic protocols**
    * **WiFi Protected Access 2 (WPA2):** an encryption scheme that implemented the CCMP.
    * **WiFi Protected Access 3 (WPA3):** released in 2018 to address the weaknesses in WPA2. Uses a much stronger 256-bit Galois/Counter Mode Protocol (GCMP-256) for encryption.
    > Two versions: WPA3-Personal for home users, and WPA3-Enterprise for corporate users.
    * **Counter-mode/CBC-MAC Protocol (CCMP):** created to replace WEP and TKIP/WPA. Uses Advanced Encryption Standard (AES) with a 128-bit key.
    * **Simultaneous Authentication of Equals (SAE):** used with WPA3-Personal and replaced WPA2-PSK (protects agains brute-force attacks). Uses a secure Diffie Hellman handshake called dragonfly. Uses perfect forward secrecy (PFS), so immune to offline attacks.
* **Authentication protocols**
    * **Extensible Authentication Protocol (EAP):** an authentication framework that allows for new authentication technologies to be compatible with existing wireless or point-to-point connection technologies.
    * **Protected Extensible Authentication Protocol (PEAP):** encapsulates EAP methods within a TLS tunnel that provides authentication and potentially encryption.
    * **EAP-FAST:** developed by Cisco, used in wireless networks and point-to-point connections to perform session authentication.
    * **EAP-TLS:** a secure version of wireless authentication that requires X509 certification. Involves 3 parties: the supplicant (user's device), the authenticator (switch or controller), and the authentication server (RADIUS server).
    * **EAP-TTLS:** uses two phases: the first is to set up a secure session with the server, by creating a tunnel, utilizing certificates that are seamless to the client. Second phase uses a protocol such as MS-CHAP to complete the session.
    > Designed to connect older, legacy systems.
    * **IEEE 802.1X:** transparent to users because it uses certificate authentication. Can be used in conjunction with a RADIUS server for enterprise networks.
    * **Remote Authentication Dial-in User Service (RADIUS) Federation:** enables members of one organization to authenticate to another with their normal credentials. Trust is across multiple RADIUS servers across multiple organizations.
    > A federation service where network access is gained using wireless access points (WAPs). WAP forwards the wireless device's credentials to the RADIUS server for authentication. Commonly uses 802.1X are the authentication method (which relies on EAP).
* **Methods**
    * **Pre-shared key (PSK) vs. Enterprise vs. Open:** PSK was introduced to the home user who does not have an enterprise setup. The home user enters the password of the wireless router to gain access to the home network. Enterprise; a corporate version of WPA2 or WPA3, used in a centralized domain environment. Often where a RADIUS server combines with 802.1X, using certificates for authentication. Open; allows any device to authenticate and then attempt to communicate with the access point.
    * **WiFi Protected Setup (WPS):** password is already stored and all you need to do is press the button to get connected to the wireless network.
    > Password is stored locally, so could be brute-forced.
    * **Captive portals:** WiFi redirects users to a webpage when they connect to SSID. Users provide additional validation of identity, normally through an emai address or social identity.
    > Common in airports and public spaces. May include acceptable use policy and premium upgrade offer.
* **Installation considerations**
    * **Site surveys:** the process of investigating the presence, strength, and reach of wireless access points deployed in an environment.
    > Usually involves walking around with a portable wireless device, taking note of the wireless signal strength, and mapping this on a plot or schematic of the building.
    * **Heat maps:** a visual representation of the wireless signal coverage and strength.
    * **WiFi analyzers:** helps track and analyze your wireless network's performance.
    * **Channel overlaps:** choose different channels per device so that there are no conflicts between access points.
    * **Wireless access point (WAP) placement:** if you're installing a new access point, you want to make sure that you place it in the right location. Minimal overlap with other access points and maximize the coverage that's being used in your environment. Avoid placement near electronic devices that could create interference, and areas where signals can be absorbed.
    > This should minimize the number of physical access points needed.
    * **Controller and access point security:** a wireless controller enables central management of configuration of access points, and security patches and firmware updates. Use HTTPS to encrypt traffic to controller and WAP web interfaces. Use strong authentication methods on the access points themselves.
# 3.5 Given a scenario, implement secure mobile solutions.
* **Connection methods and receivers**
    * **Cellular:** networks such as 4G and 5G that provide mobile devices with wireless connectivity through service providers.
    * **WiFi:** wireless local are networking technology that allows devices to connect to the internet or other devices within a specific range.
    * **Bluetooth:** short-range wireless communication technology commonly used for connecting peripherals like keyboards, headsets, or transferring files between devices.
    * **NFC:** near field communication; short-range communication technology for contactless data exchange between devices. Often used in mobile payments.
    * **Infrared:** Older technology using infrared light for short-range communication between devices.
    * **USB:** universal serial bus; a common interface for connecting devices like smartphones to computers or charging.
    * **Point-to-point:** direct communication between two devices.
    * **Point-to-multipoint:** communication from one point to multiple devices, such as broadcasting a signal.
    * **Global Positioning System (GPS):** satellite-based navigation system providing location and time information.
    * **RFID:** radio-frequency identification; technology for tracking and identifying objects using radio waves.
* **Mobile device management (MDM)**
    * **Application management:** controlling and securing mobile applications on devices.
    * **Content management:** managing and securing data and content.
    * **Remote wipe:** capability to remotely erase data on a lost or stolen device.
    * **Geofencing:** setting up virtual boundaries to trigger actions or alerts when a device enters or exits a specific area.
    * **Geolocation:** determining the physical location of a device.
    * **Screen locks:** security measures like PINs, passwords, or biometrics to lock and unlock a device.
    * **Push notifications:** messages or alerts sent from a server to a mobile device.
    * **Passwords and PINs:** authentication methods to secure access to the device.
    * **Biometrics:** authentication using unique physical or behavioral characteristics, like fingerprint or facial recognition.
    * **Context-aware authentication:** authentication based on contextual factors like location or time.
    * **Containerization:** isolating work and personal data in separate containers on a device.
    * **Storage segmentation:** dividing storage space for different purposes or security levels.
    * **Full device encryption:** encrypting all data on the device to protect against unauthorized access.
* **Mobile devices**
    * **MicroSD hardware security module (HSM):** hardware module to enhance the security of data stored on a MicroSD card.
    * **MDM/Unified Endpoint Management (UEM):** managing and securing mobile devices through centralized software.
    * **Mobile application management (MAM):** controlling and securing mobile applications within an enterprise.
    * **SEAndroid:** Security-Enhanced Android, a version of the Android OS with additional security features.
* **Enforcement and monitoring of**
    * **Third-party application stores:** controlling access to app stores other than the official ones, ensuring apps are from trusted sources.
    * **Rooting/jailbreaking:** bypassing device restrictions to gain elevated privileges, posing security risks.
    * **Sideloading:** installing applications from sources other than official app stores.
    * **Custom firmware:** modified OS software, potentially introducing security vulnerabilities.
    * **Carrier unlocking:** allowing a device to be used on different mobile carriers.
    * **Firmware over-the-air (OTA) updates:** updating device firmware wirelessly to patch security vulnerabilities.
    * **Camera use:** monitoring and controlling access to a device's camera.
    * **SMS/Multimedia Messaging Service (MMS)/Rich Communication Services (RCS):** managing and securing messaging services.
    * **External media:** controlling access to external storage devices like USB devices.
    * **USB On-The-Go (USB OTG):** allowing mobile devices to act as hosts for USB peripherals.
    * **Recording microphone:** monitoring and controlling access to a device's microphone.
    * **GPS tagging:** managing and controlling location-based services.
    * **WiFi direct/ad hoc:** allowing devices to connect directly without a wireless access point.
    * **Tethering:** sharing a device's internet connection with other devices.
    * **Hotspot:** creating a wireless access point for other devices to connect to.
    * **Payment methods:** securing mobile payment options and transactions.
* **Deployment models**
    * **Bring your own device (BYOD):** allowing employees to use their personal devices for work purposes.
    * **Corporate-owned personally enabled (COPE):** companies providing and controlling devices used for both personal and work purposes.
    * **Choose your own device (CYOD):** employees selecting from a list of approved devices for work purposes.
    * **Corporate-owned:** companies providing and controlling devices solely for work purposes.
    * **Virtual desktop infrastructure (VDI):** running desktop environments on a server, accessed remotely from a mobile device.
# 3.6 Given a scenario, apply cybersecurity solutions to the cloud.
# 3.7 Given a scenario, implement identity and account management controls.
# 3.8 Given a scenario, implement authentication and authorization solutions.
# 3.9 Given a scenario, implement public key infrastructure.