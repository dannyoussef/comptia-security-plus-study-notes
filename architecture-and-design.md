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
    * **Geographic dispersal:** placing physical servers in geographically diverse data centers to safeguard against catastrophic events and natural disasters and load balance traffic for optimal performance.
    * **Disk**
        * **Redundant array of inexpensive disks (RAID) levels:** a data storage virtualization technology that combines multiple physical disk drive components into one or more logical units for the purposes of data redundance, performance improvements, etc.
        * **Multipath:** establishing multiple physical routes between a server and the storage device that supports it.
    * **Network**
        * **Load balancers:** distribute a set of tasks over a set of resources, with the aim of making their overall processing more efficient
        * **Network interface card (NIC) teaming:** grouping physical network adapters to improve performance and redundancy.
        > NIC teaming increases the available bandwidth in a network path.
    * **Power:**
        * **Uninterruptible power supply (UPS):** a standby battery that provides power when the primary power fails.
        > Designed to keep systems running for a limited period of time, enabling graceful system shutdown. Protects systems and data from damage.
        * **Generator:** a standby power source that is powered by diesel, gasoline, propane, or natural gas.
        > Can be used to provide electricity for an extended period of time, when power from the grid fails.
        * **Dual supply:** two identical power supplies that have the capacity to run on their own and keep the server running, should one goes down.
        * **Managed power distribution units (PDUs):** a device that provides multiple power outlets (for power cable plugs). Includes network connectivity for remote connection and management of the power outlets.
        > Distributes clean power to multiple, critical network resouces, such as servers, routers, switches, and data centers.
* **Replication:** a method wherein data is copied from one location to another.
    * **Storage area network:** a hardware device that contains a large number of fast disks (e.g., SSDs), usually isolated from the LAN on its own network.
    > Provide an extra measure of redundance in case a main storage system fails.
    * **VM:** where a copy of a VM is copied across to another physical host.
    > With live migration, VM files can be copied across onto a second physical host with no downtime.
* **On-premises vs. cloud:** storage replication in the cloud is often a simple-level selection and VM replication is greatly simplified.
> Cloud reduces infrastructure complexity, but can come at an additional cost.
* **Backup types**
    * **Full:** a complete copy of a business or organization's data assets in their entirety.
    * **Incremental:** only copies data that has been changed or created since the previous backup activity was conducted.
    * **Snapshot:** uses the fast copying technology of a storage device to perform the data copying portion of the backup.
    * **Differential:** copies only newly added and changed data since the last full backup.
    > Requires more time to complete and more storage space compared to incremental backups. 
    * **Tape:** backup to a magnetic tape, is the slowest form of restore.
    > Can be stored offsite with a vaulting service in a fireproof vault.
    * **Disk:** backup to a USB, removable hard drive, or disk on another server.
    * **Copy:** uxing xcopy/robocopy to copy to another server on the network.
    > Useful in one-off/ad hoc scenarios.
    * **Network-attached storage (NAS):** allows access to storage drives via a network.
    > A good solution for large volume of data (multiple terabytes).
    * **Storage-area network:** good for fast backups of large datasets, common with SQL databases or email.
    * **Cloud:** a service that replicates your company's data to cloud-based storage and can be used for disaster recovery or to keep a copy of your data off-site.
    * **Image:** creates a copy of an OS and all the data associated with it, including the system state and application configurations.
    * **Online vs. offline:** online backups involve entrusting data to cloud storage provider. Offline backups take a tangible approach, storing data on physical devices like external hard drives.
    * **Offsite storage**
        * **Distance considerations:** must be considered in planning, such as travel time for retrieving tapes.
* **Non-persistence:** refers to systems that are not permanent and can be returned to a previous state.
    * **Revert to known state:** returning to a known working condition.
    * **Last known-good configuration:** useful restoration option shipped with all versions of Windows. Gives access to the computer when it is not able to boot on its own due to any number of problems.
    > In Windows, the new last know-good is created at each login.
    * **Live boot media:** a copy of the OS is saved to a USB flash drive or DVD. Enables booting from the removable media.
* **High availability**
    * **Scalability:** the ability of a system to handle growth of users or work.
* **Restoration order:** establishing the order in which components, systems, and services should be restored based on defined criteria.
> Generally, critical systems will be restored first.
* **Diversity**
    * **Technologies:** different technologies in service deliver (OS, apps, appliances).
    * **Vendors:** getting a service from multiple (different) providers at the same time.
    * **Crypto:**  when a company uses multiple algorithms to protect their data.
    * **Controls:** implements a compensating (backup) control that could replace a primary control should it fail.
# 2.6 Explain the security implications of embedded and specialized systems.
* **Embedded systems:** a computer system that has a dedicated function within a larger mechanical or electronic system.
    * **Raspberry Pi:** a small, single-board computer.
    * **Field-programmable gate array (FPGA):** a type of integrated circuit that can be reprogrammed after manufacturing.
    * **Arduino:** an electronic board with a simple microcontroller.
* **Supvervisory control and data acquisition (SCADA)/Industrial control system (ICS)** SCADA; used for controlling, monitoring, and analyzing industrial devices and processes. ICS; an electronic control system and associated instrumentation used for industrial process control.
    * **Facilities**
    * **Industrial**
    * **Manufacturing**
    * **Energy**
    * **Logistics**
    > In an industrial, manufacturing, or public utility settings, equipment is often network-connected and monitored. It can all be centrally configured, controlled, and monitored from a computer using a SCADA network.
* **Internet of Things (IoT):** a class of devices connected to the internet in order to provide automation, remote control, or AI processing in a home or business setting.
    * **Sensors:** gather information so devices can be used remotely and data can be shared in real time.
    * **Smart devices:** mobile devices that offer customization options, typically through installing apps, and may use on-device or cloud AI processing.
    * **Wearables:** include devices like fitness trackers or smart watches.
    * **Facility automation:** in a large facility, IoT devices can manage the heating and AC, lights, and motion/fire/water detection.
    * **Weak defaults:** devices put on a network to manage have a default username and password that are often open and available for anybody to use.
    > Botnets and offensive security tools will find and exploit devices with these still in place.
* **Specialized**
    * **Medical systems:** covers everything from small, implantable devices, to tools for measuring vitals and MRI machines.
    * **Vehicles:** modern vehicles have sensors monitoring functions or surroundings.
    * **Aircraft:** similar set of specialized embedded system; many different networks and sensors communicating with one another.
    * **Smart meters:** systems that monitor water, electricity, and other types of utility use.
* **Voice over IP (VoIP):** a technology that allows you to make voice calls using a broadband internet connection instead of a regular (or analog) phone line.
> IP phones can be entry points into a business network and are susceptible to data network attacks.
* **Heating, ventilation, air conditioning (HVAC):** large HVAC implementations have computers that monitor and maintain all of the HVAC for the facility.
> Play a huge role in human safety, so security in HVAC and HVAC monitoring systems is critical.
* **Drones:** may be manually controlled or have autonomous functions not requiring human intervention.
> A federal license is required to fly ones of a specific size in the United States.
* **Multifunction printer (MFP):** MFP can have scanning, fax, and printing capabilities with a single embedded device.
> Scans and faxes are stored somewhere on the device, usually within the internal memory. Logs on the device can also provide an attacker with a list of users and endpoints the device has communicated with.d
* **Real-time operating system (RTOS):** an OS that guarantees real-time applications a certain capability within a specified deadline.
> Designed for critical systems and for devices like microcontrollers that are timing-specific.
* **Surveillance systems:** cameras and monitoring systems. May have motion sensitive functionality, or even object tracking capabilities.
* **System on chip (SoC):** a complete computer system miniturized on a single integrated circuit, providing full computing platform on a chip.
* **Communication considerations**
    * **5G:** faster speeds and lower latency.
    > Doesn't identify each user through their SIM card, unlike 4G.
    > Because scale of IoT endpoint counts on 5G is exponentially greater, DDoS is a concern.
    * **Narrow-band:** signals that occupy a narrow range of frequencies or have that have a small fractional bandwidth.
    > Examples include RFID or keyless vehicle entry products.
    * **Baseband radio:** used for audio signals over a radio frequency. Transmitted over a single channel.
    > Example: Truck drivers communicate with one another on a specific channel.
    * **Subscriber identity module (SIM) cards:** small computer chips that contain the information about mobile subscription. Allows users to connect to telecommunication provider to make calls, sends texts, or use the internet.
    * **Zigbee:** a short-tange wireless PAN technology, developed to support automation, machine-to-machine communication, and remote control and monitoring of IoT devices.
* **Constraints**
    * **Power:** limited size.
    * **Compute:** remote/unusual locations results in limited compute capacity and low power consumption.
    * **Network:** embedded systems are not scalable, and some can only communicate through Wi-Fi or Bluetooth, and are short-ranged.
    * **Crypto:** PKI needs at least a 32-bit processor and embedded devices are limited to 8 or 16.
    * **Inability to patch:**
    * **Authentication:** some embedded devices are incapable of joining a network and may only support local logon.
    > Making changing defaults a priority.
    * **Range:** many have a very short range and are not flexible or scalable in terms of management and use.
    * **Cost:** are mainly customized and function-specific to keep costs down, making upgrade to new hardware versions impractical.
    * **Implied trust:** there is implied trust that a system functions as documented.
    > Asking manufacturer if they have been penetration tested is important.
# 2.7 Explain the importance of physical security controls.
* **Bollards/barricades:** short posts used to divert vehicle traffic from an area or road. Can be placed in front of a building to stop a car from driving at desired point.
* **Access control vestibules:** turnstile devices that only allow one person in at a time
> Mantraps are a common example.
* **Badges:** a form of identification that is retained (captured/photocopied) and used to regulate entry into buildings or restricted areas.
> A visitor may receive a different badge then that of an employee's (e.g., different color), and return it when they leave.
* **Alarms:** burglar alarms that triggers when someone attempts to break into non-occupied premises and notifies the monitoring company or police.
> Fire alarms or smoke detectors should also be present in company buildings so that people are notified to leave, in case a fire breaks out.
* **Signage:** used as a deterrent to prevent possible intruders, warning them that they are entering a secure area.
* **Cameras:** often used as a detective and deterrent control for physical security.
    * **Motion recognition:** usually set up in areas around the perimiter and on doorways to detect motion.
    * **Object detection:** can be set up to detect objects both day and night to alert the security team by raising an alarm.
* **Closed-circuit television (CCTV):** can be used to compare the audit trails and access logs with a visually recorded history of the events.
> Audit trails and visitor access logs are useful tools for managing physical access controls.
* **Industrial camoflauge:** designing a facility or other resources to obscure it from identification via aerial photography and/or other means of observation.
> Entrances will often be disguised as well to prevent visual identification by potential attackers or intruders.
* **Personnel**
    * **Guards:** typicall work at the entrance reception desk to check the identity of people entering the building to stop unauthorized access.
    * **Robot sentries:** autonomous mobile security robots that can be used to patrol the facility perimeter and raise warnings to deter any intruders or alert security staff.
    * **Reception:** the desk/station at facility entrance where guards will check employees and visitors.
    * **Two-person integrity/control:** requiring the presence of at least two authorized persons to enable access to certain resources.
    > Ensures that no single person would have access to any particular asset in the building, reducing tghe risk of a malicious insider attack.
* **Locks**
    * **Biometrics:** something unique about a person or their behavior (e.g., fingerprint).
    * **Electronic:** something a person has (e.g., a PIN code).
    * **Physical:** a device that prevents access to data, such as a key lock switch on a computer.
    * **Cable locks:** attached to laptops or tablets to secure them against theft.
* **USB data blocker:** device that blocks the data pins on the USB device, which prevents attacks in unsecure scenarios.
> Can prevent juice jacking, where data is stolen when you are chargin a USB device in a public are.
* **Lighting:** attackers avoid any place that may be lit.
> Proper lighting is important in environments that need to be monitored 24 hours a day. Consider lighting angles if there are shadows and some type of facial recognition is enabled.
* **Fencing:** protect resources for which access should be restricted.
> Height and material will factor in how effective a fence will be in access prevention: 3-4 feet deters the casual trespasser, 6-7 may be too difficult to climb easily and may block vision, 8-feet (topped with barbed wire) will deter determined intruders.
* **Fire suppression:** human safety is priority. Proper monitoring and warning, consisting of fire detection and fire alarms, and clearly marked fire exits ensure employees and visitors to evacuate safely from facilities in the event of a fire.
* **Sensors**
    * **Motion detection:** when someone is walking past a building and the motion sensors detect movement and turn on lights to discourage would-be intruders.
    * **Noise detection:** noise monitoring devices can detect excessive noise to detect a variety of issues, depending on placement, including intruders or other negative events.
    * **Proximity Reader:** commonly used to gain access to doors, or door locks.
    * **Moisture detection:** humidity sensors measure the amount of moisture in the air.
    > Too much moisture in the air could lead to condensation, which can damage sensitive equipment and lead to formation of harmful mold.
    * **Cards:** moving the proximity card closer to the proximity reader, info on the card is checked, and then the system can either allow or disallow access through that lock.
    * **Temperature:** temperature sensors detect that it is getting too hot, it can trigger corrective action, such as injecting cold air into a space.
    > Critical systems could fail if the temperature gets too hot.
* **Drones:** used to monitor facility perimeters and conduct constant surveillance over large areas.
> Can also be sent out as a response mechanism before personnel can respond and conduct an initial site assessment.
* **Visitor logs:** required if a facility employs restricted areas to control physical security. Guards at the main entrance will ask visitors to complete the visitor logs, and then provide some form of identification.
> An escort is often assigned to visitors, and their access and activities are monitored closely.
* **Faraday cages:** an enclosure used to block electromagnetic fields. Prevents wireless or cellular phones from working inside the enclosure.
> Signals, such as a HF RFID, are likely to break through a Faraday cage.
* **Air gap:** a security measure that involves isolating a computer or network and preventing it from establishing an external connection.
> The only way to insert or removed data from an air-gapped machine is by using removable media (e.g., USB or CD-ROM drive).
* **Screened subnet (previously known as demilitarized zone):** a boundary layer between the LAN and the WAN that holds information that companies may want people from the internet to access.
> Front-end web and email servers may reside in a screened subnet. Systems with sentive data or hosting identiy and access management would not (e.g., Active Directory).
* **Protected cable distribution:** also known as a protected distribution system (PDS); encases network cabling within a carrier. Enables data to be securely transferred directly between two high-security areas through an area of lower security.
* **Secure areas:**
    * **Air gap:** create "air gaps" between some systems are used internally to separate confidential systems from standard systems.
    * **Vault:** where data can be encrypted and stored in the cloud, enabling an extra-secure storage area.
    * **Safe:** safes for the storage of laptops and tablets.
    * **Hot aisle:** hot air is allowed to escape through a vent or chimney (or may be captured and channeled back to HVAC unit).\
    > The rear of the servers face each other, pushing hot air out into the hot aisles.
    * **Cold aisle:** where the cold air enters and is contained, it faces the front of the servers.
* **Secure data destruction:**
    * **Burning:** burning with fire, as with an incinerator on site or via a third-party vendor providing a destruction certificate.
    * **Shredding:** can shred a metal hard drive into powder or a paper into shreds, making reassembly much more difficult.
    * **Pulping:** a technique opf destroying paper documents by soaking them in water and grinding them into pulp, used if burning is not an option.
    * **Pulverizing:** using a hammer and smashing drive into pieces, or drill through all the platters.
    * **Degaussing:** creates a strong magnetic field that erases data on some media and destroys electronics.
    * **Third-party solutions:** a third-party vendor may provide data destruction services.
# 2.8 Summarize the basics of cryptographic concepts.
* **Digital signatures:**
* **Key length:**
* **Key stretching:**
* **Salting:**
* **Hashing:**
* **Key exchange:**
* **Elliptic-curve cryptography:**
* **Perfect forward secrecy:**
* **Quantum**
    * **Communications:**
    * **Computing:**
* **Post-quantum:**
* **Ephemeral:**
* **Modes of operation**
    * **Authenticated:**
    * **Unauthenticated:**
    * **Counter:**
* **Blockchain**
    * **Public ledgers:**
* **Cipher suites:**
    * **Stream:**
    * **Block:**
* **Symmetric vs. asymmetric:**
* **Lightweight cryptography:**
* **Steganography**
    * **Audio:**
    * **Video:**
    * **Image:**
* **Homomorphic encryption:**
* **Common use cases**
    * **Low power devices:**
    * **Low latency:**
    * **High resiliency:**
    * **Supporting confidentiality:**
    * **Supporting integrity:**
    * **Supporting obfuscation:**
    * **Supporting authentication:**
    * **Supporting non-repudiation:**
* **Limitations**
    * **Speed:**
    * **Size:**
    * **Weak keys:**
    * **Time:**
    * **Longevity:**
    * **Predictability:**
    * **Reuse:**
    * **Entropy:**
    * **Computational overheads:**
    * **Resource vs. security constraints:**
