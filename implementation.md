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
# 3.3 Given a scenario, implement secure network designs.
# 3.4 Given a scenario, install and configure wireless security settings.
# 3.5 Given a scenario, implement secure mobile solutions.
# 3.6 Given a scenario, apply cybersecurity solutions to the cloud.
# 3.7 Given a scenario, implement identity and account management controls.
# 3.8 Given a scenario, implement authentication and authorization solutions.
# 3.9 Given a scenario, implement public key infrastructure.