# 2.1 Explain the importance of security concepts in an enterprise environment.
* **Configuration management**
    * **Diagrams:** visual representations aiding in understanding system architectures, network topologies, and security controls.
    * **Baseline configuration:** a set of specifications for an information system or configuration item that has been formally reviewed and agreed on at a given point in time, and which can be changed only through change control procedures.
    * **Standard naming conventions:** consistent and standardized naming conventions.
    * **Internet protocol (IP) schema:** well-organized IP addressing to simplify network management.
* **Data sovereignty:** the idea that data are subject to the laws and governance structures of the nation where they are collected.
* **Data protection**
    * **Data loss prevention (DLP):** refers to the strategies, processes, and technologies cybersecurity teams use to protect sensitive data from theft, loss, and misuse.
    * **Masking:** the process of modifying sensitive data in such a way that is is of no or little value to unauthorized intruders while still being usable by software or authorized personnel.
    * **Encryption:** the security method of encoding data from plaintext to ciphertext.
    * **At rest:** the state of data when it is stored, rather from moving one place to another.
    * **In transit/motion:** refers data that flows between systems.
    * **In processing:** refers to data as it is being processed.
    * **Tokenization:** the process of substituting a sensitive data element with a non-sensitive equivalent (token) that has no intrinsic or exploitable meaning or value.
    * **Rights management:** the use of technology to control and manage copyrighted material.
* **Geographical considerations:** ensures compliance with data protection laws related to the storage and processing of data in specific geographic locations.
* **Response and recovery controls:** organized strategic approach to detecting and managing cyber attacks in ways that minimize damage, recovery time, and total costs.
* **Secure Sockets Layer (SSL)/Transport Layer Security (TLS) Inspection:** the process of intercepting and reviewing encrypted internet communication traffic.
* **Hashing:** the practice of transforming a given key or string of characters into another value for the purpose of security.
* **API Considerations:** securing APIs through authentication, authorization, and encryption to prevent unauthorized access and data exposure.
* **Site resiliency**
    * **Hot site:** an off-premises location where an organization can resume normal operations in the event of an information system disruption.
    * **Cold site:** a backup facility that has the necessary electrical and physical components of a computer facility, but does not have the computer equipment in place.
    * **Warm site:** an environmentally conditioned work space that is partially equipped with information systems and telecommunications equipment to support relocated operations in the event of a significant disruption.
* **Deception and disruption**
    * **Honeypots:** a system or system resource that is designed to be attractive to potential crackers and intruders.
    * **Honeyfiles:** bait files intended for hackers to access.
    * **Honeynets:** a network of decoy computer systems that are used to lure in attackers and gather threat intelligence.
    * **Fake telemetry:** contains decoy or faked telemetry data that can be used to entice attackers while simultaneously capturing data on and about the attack.
    * **DNS sinkhole:** a mechanism aimed at protecting users by intercepting DNS requests attempting to connect to known malicious or unwanted domains and return a false, or rather controlled IP address.
# 2.2 Summarize virtualization and cloud computing concepts.
* **Cloud models**
    * **Infrastructure as a service (IaaS):** a cloud computing service model by means of which computing resources are supplied by a cloud services provider.
    * **Platform as a service (Paas):** a complete cloud environment that includes everything developers need to build, run, and manage applications (from servers and operating systems, to networking, storage, tools, etc.)
    * **Software as a service (SaaS):** a software licensing and delivery model in which software is licensed on a subscription basis and is centrally hosted.
    * **Anything as a service (AaaS):** a general category of services related to cloud computing and remote access.
    * **Public:** an IT model where on-demand computing services and infrastructure are managed by a third-party provider and shared with multiple organizations using the public internet.
    * **Community:** a cloud infrastructure in which multiple organizations share resources and services based on common operational and regulatory requirements.
    * **Private:** a cloud computing environment dedicated to a single organization.
    * **Hybrid:** a mixed computing environment where applications are run using a combination of computing, storage, and services in different environments (public and private clouds).
* **Cloud service providers:** an IT company that provides on-demand, scalable computing resources like computing power, data storage, or applications over the internet.
* **Managed service provider (MSP)/managed security service provider (MSSP):** provides outsourced monitoring and management of security devices and systems.
* **On-premises vs. off-premises:** on-premise is a proposed solution hosted in-house on the users/organization system. Off-premise has hosting and support done by some other third-party.
* **Fog computing:** an architecture that use edge devices (bridge between two networks) to carry out cloud computing and services to the edge of an enterprise's network.
* **Edge computing:** a distributed computing paradigm that brings computation and data storage closer to the sources of data.
* **Thin client:** a computer that uses resources inside a central server as opposed to a hard drive.
* **Containers:** standard units of software that package up code and all its dependencies so the application runs quickly and reliably from one computing environment to another.
* **Microservices:** an architectural and organizational approach to software development where software is composed of small, independent services that communicate over well-defined APIs.
> Makes applications easier to scale and faster to develop.
* **Infrastructure code**
    * **Software-defined networking (SDN):** an approach to networking that uses software-based controllers or APIs to communicate with underlying hardware infrastructure and direct traffic on a network.
    * **Software-defined visiblity (SDV):** a network-level visibility controller that aggregates application data from multiple devices and sources and provides composite application information.
* **Serverless architecture:** a way to build and run applications and services without having to manage infrastructure.
* **Services integration:** an approach to managing multiple suppliers of services and integrating them to provide a single business-facing IT organization.
* **Resource policies:** allow you to specify who can access a specific resource.
* **Transit gateway:** a network transit hub that you can use to interconnect your virtual private clouds (VPCs) and on-premises networks.
* **Virtualization**
    * **Virtual machine (VM) sprawl avoidance:** the uncontrolled growth of virtual machines within an environment.
    > Sometimes, organizations end up with a large number of VMs that are underutilized, not properly managed, or even forgotten.
    * **VM escape protection:** VM escape is the process of a program breaking out of the virtual machine on which it is running and interacting with the host operating system.
    > Allows someone on one VM to gain access to resources on a separate VM.
    > Updating software regularly and installing patches reduces the risk of exploiting this.
# 2.3 Summarize secure application development, deployment, and automation concepts.
* **Environment**
    * **Development:** a workspace for developers to make changes without breaking anything in a live environment.
    * **Test:** an environment where the testing teams analyze the quality of the application/program.
    * **Staging:** the last step before an application goes into production, meant to ensure that all new changes deployed from previous environments are working as intended.
    * **Production:** a real-time setting where the latest versions of software, products, or updates are pushed into live, usable operations for the intended end users.
    * **Quality assurance (QA):** an environment where you test your upgrade procedures against data, hardware, and software that closely simulate the production environment and where you allow intended users to test the resulting application.
* **Provisioning and deprovisioning:** provisioning refers to onboarding new users (creating user account, providing access, etc.). Deprovisioning applies to the offboarding process, revoking employee access when needed.
* **Integrity measurement:** responsible for collecting file hashes, placing them in kernel memory (where userland applications cannot access/modify it) and allows local and remote parties to verify the measured values.
* **Secure coding techniques**
    * **Normalization:** the moving of units of data from one place to another in your relational schema (i.e., organization data in a database).
    * **Stored procedures:** a prepared SQL code that you can save, so the code can be reused.
    > Used for data validation and/or access control mechanisms.
    * **Obfuscation/camouflage:** the act of creating source or machine code that is difficult for humans or computers to understand.
    * **Code reuse/dead code:** code reuse can cause dead code since not all interfaces or functions may be used.
    > Dead code is code that is never executed and should be optimized out of a program (wastes computation time and memory).
    * **Server-side vs. client-side execution and validation:** client-side provides instant feedback to the user, while server-side ensures that all data is validated correctly.
    > Combining both creates a robust validation system that ensures the integrity and security of the data.
    * **Memory management:** the process of controlling and coordinating a computer's main memory. It ensures that blocks of memory space are properly managed and allocated, so the OS, applications, and other running processes have the memory they need.
    * **Use of third-party libraries and software development kits (SDKs):** important to evaluate the code for any security bugs, since they can be a big security risk for proprietary software products.
    * **Data exposure:** a security violation, in which sensitive information is copied, transmitted, viewed, altered, oor stole by an unauthorized individual.
* **Open Web Application Security Project (OWASP):** the online community that produces freely available articles, methodologies, documentation, tools, and technologies in the field of web application security.
* **Software diversity:** creation of software that's different on each user endpoint/device.
    * **Compiler:** dynamic paths in compiler at compile time.
    * **Binary:** results in a binary that is slightly different on every endpoint.
> Makes the process of exploiting a software vulnerability more difficult for attackers.
* **Automation/scripting:** processes designed to carry out tasks automatically without the need for human intervention.
    * **Automated courses of action:** refers to an automated series of steps or activities performed in order to produce consistent results.
    * **Continous monitoring:** an approach whwere an organization constantly monitors its IT systems and networks to detect security threats, performance issues, or non-compliance problems in an automated manner.
    * **Continous validation:** testing to make sure that automated processes fit their purpose and fulfill the user's requirements, and that security requirements are met.
    * **Continous integration:** the practice of merging all developers' working copies to a shared mainline several times a day, after which automated builds and tests are run.
    * **Continous delivery:** a software development practice where code changes are automatically prepared for a release to production.
    * **Continous deployment:** a strategy in software development where code changes to an application are released automatically into the production environment.
* **Elasticity:** the ability of a system to automatically grow and shrink based on app demand.
* **Scalability:** the ability of a system to handle growth of users or work.
* **Version control:** the practice of tracking and managing changes to software code.
> Ensures new and older versions of the software can be identified and allows security team to track security vulnerabilities and vendor support.
# 2.4 Summarize authentication and authorization design concepts.
* **Authentication methods**
    * **Directory services:** used to store, retrieve, and manage information about objects, such as user accounts, computer accounts, mail accounts, and information on resources.
    * **Federation:** linking a user's identify across multiple separate identity management systems.
    * **Attestation:** the process of confirming the device (laptop, phone, etc.) is an approved device compliant with company policies.
    * **Technologies**
        * **Time-based one-time password (TOTP):** a computer algorithm that generates a one-time password that uses the current time as a source of uniqueness. 
        > An extension of the HMAC-based one-time password algorithm. Uses time in increments called the timestep, which is usually 30 or 60 seconds. Each OTP is valid for the duration of the timestep.
        * **HMAC-based one-time password (HOTP):** uses a keyed-hash message authentication code (HMAC) that relies on the seed, a secret known only by the token and validating server, and a moving factor, a counter.
        * **Short message service (SMS):** used as an additional layer of security where the user is authenticated, and an SMS message is sent to the user's mobile phone.
        * **Token key:** one-time password provided on a hardware of software token generator.
        > Authenticator apps are a common software solution for token keys.
        * **Static codes:** a static set of numbers and letters to provide for authentication.
        > A password or paraphrase is an example of an alphanumeric static code.
        * **Authentication applications:** a software-based authenticator that implements two-step verification services using the TOTP and HOTP algorithms for authenticating users of software applications.
        > Examples include Microsoft Authenticator and Google Authenticator.
        * **Push notifications:** when the server is pushing down the authentication information to your mobile device.
        > Uses the mobile device app to be able to receive the pushed message and display the authentication information.
        * **Phone call:** an authentication method in which an automated process calls you, waiting for a response with a pin or other input via voice or keypad.
    * **Smart card authentication:** a credit-card-sized token that contains a certificate and is used for authentication in conjunction with a PIN.
    > Generally requires physical proximity or insertion into reader.
* **Biometrics**
    * **Fingerprint:** verifying an individual's identity based on one or more of their fingerprints.
    * **Retina:** uses the unique patterns on a person's retina blood vessels.
    * **Iris:** involves capturing an image of a user's iris.
    * **Facial:** a way of identifying or confirming an individual's identity using their face.
    * **Voice:**
    * **Vein:** using blood vessels in the palm.
    * **Gait analysis:** identification using gait (the way an individual walks).
    * **Efficacy rates:** refers to the overall accuracy of a biometric authentication method.
    * **False acceptance:** occurs when an invalid subject is authenticated.
    * **False rejection:** occurs when a valid subject is rejected.
    * **Crossover error rate:** the overall accuracy of a biometric system. It shows where the false rejection rate is equal to the false acceptance rate.
    > FAR is the false acceptance rate, FRR is the false rejection rate.
* **Multifactor authentication (MFA) factors and attributes:** works by requiring two or more of the following authentication methods.
    * **Factors**
        * **Something you know:** pin or password.
        * **Something you have:** trusted device.
        * **Something you are:** biometric (fingerprint).
    * **Attributes**
        * **Somewhere you are:** your expected location, such as the company office, home, or home city.
        * **Something you can do:** such as writing your signature.
        * **Something you exhibit:** the personalized manner you perform an action, such as gait.
        * **Someone you know:** responding to a challenge with knowledge of a characteristic of a specific individual you know.
* **Authentication, authorization, and accounting (AAA):** security framework that controls access to computer resources, enforces policies, and audits usage. With AAA, network devices use a centralized RADIUS or TACACS+ server to authenticate users, authorize the commands users can run on a device, and provide accounting information.
> Authentication provided identity verification before access to a network device is granted. Authorization provides access control. Accounting provides a method for collecting information, logging the information locally on a network device, and sending it to an AAA server for billing, auditing, and reporting.
* **Cloud vs. on-premises requirements:** on-premises; the perimeter of the location is easy to establish and control. Proximity cards (badge system) and security guards at a reception can also control access to the company. Does not always assume internet access is available. Cloud; Internet access is assumed to authenticate and connect to cloud resources. The security perimeter is no longer confined to the on-premises environment.
# 2.5 Given a scenario, implement cybersecurity resilience.
* **Redundancy**
    * **Geographic disperal:**
    * **Disk**
        * **Redundant array of inexpensive disks (RAID) levels:**
        * **Multipath:**
    * **Network**
        * **Load balancers:**
        * **Network interface card (NIC) teaming:**
    * **Power:**
        * **Uninterruptible power supply (UPS):**
        * **Generator:**
        * **Dual supply:**
        * **Managed power distribution units (PDUs):**
* **Replication**
    * **Storage area network:**
    * **VM:**
* **On-premises vs. cloud:**
* **Backup types**
    * **Full:**
    * **Incremental:**
    * **Snapshot:**
    * **Differential:**
    * **Tape:**
    * **Disk:**
    * **Copy:**
    * **Network-attached storage (NAS):**
    * **Storage-area network:**
    * **Cloud:**
    * **Image:**
    * **Online vs. offline:**
    * **Offsite storage**
        * **Distance considerations:**
* **Non-persistence**
    * **Revert to known state:**
    * **Last known-good configuration:**
    * **Live boot media:**
* **High availability**
    * **Scalability:**
* **Restoration order:**
* **Diversity**
    * **Technologies:**
    * **Vendors:**
    * **Crypto:**
    * **Controls:**
# 2.6 Explain the security implications of embedded and specialized systems.
# 2.7 Explain the importance of physical security controls.
# 2.8 Summarize the basics of cryptographic concepts.
