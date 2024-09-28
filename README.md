# Awesome Honeypots [![Awesome Honeypots](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome honeypots, plus related components and much more, divided into categories such as Web, services, and others, with a focus on free and open source projects.

There is no pre-established order of items in each category, the order is for contribution. If you want to contribute, please read the [guide](CONTRIBUTING.md).

Discover more awesome lists at [sindresorhus/awesome](https://github.com/sindresorhus/awesome).

# Contents

- [Awesome Honeypots ![Awesome Honeypots](https://github.com/sindresorhus/awesome)]
- [Contents](#contents)
  - [Related Lists](#related-lists)
  - [Honeypots](#honeypots)
  - [Honeyd Tools](#honeyd-tools)
  - [Network and Artifact Analysis](#network-and-artifact-analysis)
  - [Data Tools](#data-tools)
  - [Guides](#guides)

## Related Lists

- [awesome-pcaptools](https://github.com/caesar0301/awesome-pcaptools) - Useful in network traffic analysis.
- [awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis) - Some overlap here for artifact analysis.

## Honeypots

- Web honeypots

  - ~~[Express honeypot](https://github.com/christophe77/express-honeypot) - RFI & LFI honeypot using nodeJS and express.~~ Meh, non interessante
  - ~~[EoHoneypotBundle](https://github.com/eymengunay/EoHoneypotBundle) - Honeypot type for Symfony2 forms.~~ Meh, non interessante
  - [Glastopf](https://github.com/mushorg/glastopf) - Web Application Honeypot.
  - ~~[Google Hack Honeypot](http://ghh.sourceforge.net) - Designed to provide reconnaissance against attackers that use search engines as a hacking tool against your resources.~~ Abbandonato, probabilmente deprecato
  - ~~[HellPot](https://github.com/yunginnanet/HellPot) - Honeypot that tries to crash the bots and clients th   at visit it's location.~~ Figo ma non rilevante
  - ~~[Laravel Application Honeypot](https://github.com/msurguy/Honeypot) - Simple spam prevention package for Laravel applications.~~ Carino ma non rilevante
  - ~~[Nodepot](https://github.com/schmalle/Nodepot) - NodeJS web application honeypot.~~ Mah, progetto di scuola
  - ~~[PasitheaHoneypot](https://github.com/Marist-Innovation-Lab/PasitheaHoneypot) - RestAPI honeypot.~~ worthless
  - ~~[Servletpot](https://github.com/schmalle/servletpot) - Web application Honeypot.~~ Abbandonato, worthless
  - ~~[Shadow Daemon](https://shadowd.zecure.org/overview/introduction/) - Modular Web Application Firewall / High-Interaction Honeypot for PHP, Perl, and Python apps. ~~ sito morto. Peccato, sembrava carino. 
  - ~~[StrutsHoneypot](https://github.com/Cymmetria/StrutsHoneypot) - Struts Apache 2 based honeypot as well as a detection module for Apache 2 servers.~~ specifico ad apache, non rilevante
  - ~~[WebTrap](https://github.com/IllusiveNetworks-Labs/WebTrap) - Designed to create deceptive webpages to deceive and redirect attackers away from real websites.~~ Non mi fido, penso sia meglio galah
  - ~~[basic-auth-pot (bap)](https://github.com/bjeborn/basic-auth-pot) - HTTP Basic Authentication honeypot.~~ Mah, chi mai lo usa. No potenziale
  - ~~[bwpot](https://github.com/graneed/bwpot) - Breakable Web applications honeyPot.~~ Forse figo ma in cinese
  - ~~[django-admin-honeypot](https://github.com/dmpayton/django-admin-honeypot) - Fake Django admin login screen to notify admins of attempted unauthorized access.~~ No potenziale
  - ~~[drupo](https://github.com/d1str0/drupot) - Drupal Honeypot.~~ No docs
  - [galah](https://github.com/0x4D31/galah) - an LLM-powered web honeypot using the OpenAI API. **JACKPOT**
  - ~~[honeyhttpd](https://github.com/bocajspear1/honeyhttpd) - Python-based web server honeypot builder.~~ È un framework, non implementa niente di specifico. Potrebbe essere utile ma lo scarto.
  - ~~[honeyup](https://github.com/LogoiLab/honeyup) - An uploader honeypot designed to look like poor website security.~~ Non mi ispira
  - ~~[modpot](https://github.com/referefref/modpot) - Modpot is a modular web application honeypot framework and management application written in Golang and making use of gin framework.~~ È solo un framework
  - ~~[owa-honeypot](https://github.com/joda32/owa-honeypot) - A basic flask based Outlook Web Honey pot.~~ Puccioso, però non rilevante.
  - ~~[phpmyadmin_honeypot](https://github.com/gfoss/phpmyadmin_honeypot) - Simple and effective phpMyAdmin honeypot.~~ Manco guardato, presumo puccioso ma irrilevante.
  - ~~[shockpot](https://github.com/threatstream/shockpot) - WebApp Honeypot for detecting Shell Shock exploit attempts.~~ Specifico ad una CVE
  - ~~[smart-honeypot](https://github.com/freak3dot/smart-honeypot) - PHP Script demonstrating a smart honey pot.~~ "Smart honeypot" oh come on
  - Snare/Tanner - successors to Glastopf
    - [Snare](https://github.com/mushorg/snare) - Super Next generation Advanced Reactive honeypot.
    - [Tanner](https://github.com/mushorg/tanner) - Evaluating SNARE events.
  - ~~[stack-honeypot](https://github.com/CHH/stack-honeypot) - Inserts a trap for spam bots into responses.~~ irrilevante
  - ~~[tomcat-manager-honeypot](https://github.com/helospark/tomcat-manager-honeypot) - Honeypot that mimics Tomcat manager endpoints. Logs requests and saves attacker's WAR file for later study.~~ Non mi interessa tomcat
  - ~~[Python-Honeypot](https://github.com/OWASP/Python-Honeypot) - OWASP Honeypot, Automated Deception Framework.~~ Solo un framework (credo) / non un honeypot

- Service Honeypots
  - [ddospot](https://github.com/aelth/ddospot) - NTP, DNS, SSDP, Chargen and generic UDP-based amplification DDoS honeypot.
  - [dionaea](https://github.com/DinoTools/dionaea) - Home of the dionaea honeypot.
  - [dhp](https://github.com/ciscocsirt/dhp) - Simple Docker Honeypot server emulating small snippets of the Docker HTTP API.
  - [DolosHoneypot](https://github.com/Marist-Innovation-Lab/DolosHoneypot) - SDN (software defined networking) honeypot.
  - [Ensnare](https://github.com/ahoernecke/ensnare) - Easy to deploy Ruby honeypot.
  - [Helix](https://github.com/Zeerg/helix-honeypot) - K8s API Honeypot with Active Defense Capabilities.
  - [honeycomb_plugins](https://github.com/Cymmetria/honeycomb_plugins) - Plugin repository for Honeycomb, the honeypot framework by Cymmetria.
  - [honeydb] (https://honeydb.io/downloads) - Multi-service honeypot that is easy to deploy and configure. Can be configured to send interaction data to to HoneyDB's centralized collectors for access via REST API.
  - [honeyntp](https://github.com/fygrave/honeyntp) - NTP logger/honeypot.
  - [honeypot-camera](https://github.com/alexbredo/honeypot-camera) - Observation camera honeypot.
  - [honeypot-ftp](https://github.com/alexbredo/honeypot-ftp) - FTP Honeypot.
  - [honeypots](https://github.com/qeeqbox/honeypots) - 25 different honeypots in a single pypi package! (dns, ftp, httpproxy, http, https, imap, mysql, pop3, postgres, redis, smb, smtp, socks5, ssh, telnet, vnc, mssql, elastic, ldap, ntp, memcache, snmp, oracle, sip and irc).
  - [honeytrap](https://github.com/honeytrap/honeytrap) - Advanced Honeypot framework written in Go that can be connected with other honeypot software.
  - [HoneyPy](https://github.com/foospidy/HoneyPy) - Low interaction honeypot.
  - [Honeygrove](https://github.com/UHH-ISS/honeygrove) - Multi-purpose modular honeypot based on Twisted.
  - [Honeyport](https://github.com/securitygeneration/Honeyport) - Simple honeyport written in Bash and Python.
  - [Honeyprint](https://github.com/glaslos/honeyprint) - Printer honeypot.
  - [Lyrebird](https://hub.docker.com/r/lyrebird/honeypot-base/) - Modern high-interaction honeypot framework.
  - [MICROS honeypot](https://github.com/Cymmetria/micros_honeypot) - Low interaction honeypot to detect CVE-2018-2636 in the Oracle Hospitality Simphony component of Oracle Hospitality Applications (MICROS).
  - [node-ftp-honeypot](https://github.com/christophe77/node-ftp-honeypot) - FTP server honeypot in JS.
  - [pyrdp](https://github.com/gosecure/pyrdp) - RDP man-in-the-middle and library for Python 3 with the ability to watch connections live or after the fact.
  - [rdppot](https://github.com/kryptoslogic/rdppot) - RDP honeypot
  - [RDPy](https://github.com/citronneur/rdpy) - Microsoft Remote Desktop Protocol (RDP) honeypot implemented in Python.
  - [SMB Honeypot](https://github.com/r0hi7/HoneySMB) - High interaction SMB service honeypot capable of capturing wannacry-like Malware.
  - [Tom's Honeypot](https://github.com/inguardians/toms_honeypot) - Low interaction Python honeypot.
  - [Trapster Commmunity](https://github.com/0xBallpoint/trapster-community) - Modural and easy to install Python Honeypot, with comprehensive alerting
  - [troje](https://github.com/dutchcoders/troje/) - Honeypot that runs each connection with the service within a separate LXC container.
  - [WebLogic honeypot](https://github.com/Cymmetria/weblogic_honeypot) - Low interaction honeypot to detect CVE-2017-10271 in the Oracle WebLogic Server component of Oracle Fusion Middleware.
  - [WhiteFace Honeypot](https://github.com/csirtgadgets/csirtg-honeypot) - Twisted based honeypot for WhiteFace.
 
- Distributed Honeypots

  - ~~[DemonHunter](https://github.com/RevengeComing/DemonHunter) - Low interaction honeypot server.~~ Helper; non un honeypot

- Anti-honeypot stuff

  - [canarytokendetector](https://github.com/referefref/canarytokendetector) - Tool for detection and nullification of Thinkst CanaryTokens
  - [honeydet](https://github.com/referefref/honeydet) - Signature based honeypot detector tool written in Golang
  - [kippo_detect](https://github.com/andrew-morris/kippo_detect) - Offensive component that detects the presence of the kippo honeypot.

- ICS/SCADA honeypots

  - [Conpot](https://github.com/mushorg/conpot) - ICS/SCADA honeypot.
  - [GasPot](https://github.com/sjhilt/GasPot) - Veeder Root Gaurdian AST, common in the oil and gas industry.
  - [SCADA honeynet](http://scadahoneynet.sourceforge.net) - Building Honeypots for Industrial Networks.
  - [gridpot](https://github.com/sk4ld/gridpot) - Open source tools for realistic-behaving electric grid honeynets.
  - [scada-honeynet](http://www.digitalbond.com/blog/2007/07/24/scada-honeynet-article-in-infragard-publication/) - Mimics many of the services from a popular PLC and better helps SCADA researchers understand potential risks of exposed control system devices.

- Other/random

  - ~~[CitrixHoneypot](https://github.com/MalwareTech/CitrixHoneypot) - Detect and log CVE-2019-19781 scan and exploitation attempts.~~
  - ~~[Damn Simple Honeypot (DSHP)](https://github.com/naorlivne/dshp) - Honeypot framework with pluggable handlers.~~ Non interessante
  - ~~[dicompot](https://github.com/nsmfoo/dicompot) - DICOM Honeypot.~~ Troppo specifico
  - ~~[IPP Honey](https://gitlab.com/bontchev/ipphoney) - A honeypot for the Internet Printing Protocol.~~ Troppo specifico
  - ~~[Log4Pot](https://github.com/thomaspatzke/Log4Pot) - A honeypot for the Log4Shell vulnerability (CVE-2021-44228).~~
  - ~~[Masscanned](https://github.com/ivre/masscanned) - Let's be scanned. A low-interaction honeypot focused on network scanners and bots. It integrates very well with IVRE to build a self-hosted alternative to GreyNoise.~~ Mi piace un botto ed è stradivertente. Purtroppo non è rilevante al mio progetto. 
  - ~~[medpot](https://github.com/schmalle/medpot) -  HL7 / FHIR honeypot.~~
  - ~~[NOVA](https://github.com/DataSoft/Nova) - Uses honeypots as detectors, looks like a complete system.~~ Come `OpenCanary: è un semplice honeypot pure lui, ma semplicemente installato su rete interna. 
  - ~~[OpenFlow Honeypot (OFPot)](https://github.com/upa/ofpot) - Redirects traffic for unused IPs to a honeypot, built on POX.~~ Utility, la scarto.
  - ~~[OpenCanary](https://github.com/thinkst/opencanary) - Modular and decentralised honeypot daemon that runs several canary versions of services that alerts when a service is (ab)used.~~ Deluso deludendo. È semplicemente un honeypot ma deployato in una rete interna.
  - ~~[ciscoasa_honeypot](https://github.com/cymmetria/ciscoasa_honeypot) A low interaction honeypot for the Cisco ASA component capable of detecting CVE-2018-0101, a DoS and remote code execution vulnerability.~~ Troppo Specifico
  - ~~[miniprint](https://github.com/sa7mon/miniprint) - A medium interaction printer honeypot.~~ Specifico a printers

- IPv6 attack detection tool

  - ~~[ipv6-attack-detector](https://github.com/mzweilin/ipv6-attack-detector/) - Google Summer of Code 2012 project, supported by The Honeynet Project organization.~~ Non capisco cosa sia

- Dynamic code instrumentation toolkit

  - [Frida](https://www.frida.re) - Inject JavaScript to explore native apps on Windows, Mac, Linux, iOS and Android.

- Tool to convert website to server honeypots

  - [HIHAT](http://hihat.sourceforge.net/) - Transform arbitrary PHP applications into web-based high-interaction Honeypots.

- Distributed sensor deployment

  - [Community Honey Network](https://communityhoneynetwork.readthedocs.io/en/stable/) - CHN aims to make deployments honeypots and honeypot management tools easy and flexible. The default deployment method uses Docker Compose and Docker to deploy with a few simple commands.
  - [Modern Honey Network](https://github.com/threatstream/mhn) - Multi-snort and honeypot sensor management, uses a network of VMs, small footprint SNORT installations, stealthy dionaeas, and a centralized server for management.

- Network Analysis Tool

  - [Tracexploit](https://code.google.com/archive/p/tracexploit/) - Replay network packets.

- Log anonymizer

  - [LogAnon](http://code.google.com/archive/p/loganon/) - Log anonymization library that helps having anonymous logs consistent between logs and network captures.

- Low interaction honeypot (router back door)

  - [Honeypot-32764](https://github.com/knalli/honeypot-for-tcp-32764) - Honeypot for router backdoor (TCP 32764).
  - [WAPot](https://github.com/lcashdol/WAPot) - Honeypot that can be used to observe traffic directed at home routers.

- honeynet farm traffic redirector

  - [Honeymole](https://web.archive.org/web/20100326040550/http://www.honeynet.org.pt:80/index.php/HoneyMole) - Deploy multiple sensors that redirect traffic to a centralized collection of honeypots.

- HTTPS Proxy

  - [mitmproxy](https://mitmproxy.org/) - Allows traffic flows to be intercepted, inspected, modified, and replayed.

- System instrumentation

  - [Sysdig](https://sysdig.com/opensource/) - Open source, system-level exploration allows one to capture system state and activity from a running GNU/Linux instance, then save, filter, and analyze the results.
  - [Fibratus](https://github.com/rabbitstack/fibratus) - Tool for exploration and tracing of the Windows kernel.

- Honeypot for USB-spreading malware

  - ~~[Ghost-usb](https://github.com/honeynet/ghost-usb-honeypot) - Honeypot for malware that propagates via USB storage devices.~~ ~~Strapuccioso, devo mettermelo pure io. Però non è rilevante.~~ Fuck it, è solo per windows

- Low interaction honeypot

  - [Honeyperl](https://sourceforge.net/projects/honeyperl/) - Honeypot software based in Perl with plugins developed for many functions like : wingates, telnet, squid, smtp, etc.
  - [T-Pot](https://github.com/dtag-dev-sec/tpotce) - All in one honeypot appliance from telecom provider T-Mobile
  - [beelzebub](https://github.com/mariocandela/beelzebub) - A secure honeypot framework, extremely easy to configure by yaml 🚀

- Server

  - [Amun](http://amunhoney.sourceforge.net) - Vulnerability emulation honeypot.
  - [Artillery](https://github.com/trustedsec/artillery/) - Open-source blue team tool designed to protect Linux and Windows operating systems through multiple methods.
  - [Bait and Switch](http://baitnswitch.sourceforge.net) - Redirects all hostile traffic to a honeypot that is partially mirroring your production system.
  - [Bifrozt](https://github.com/Ziemeck/bifrozt-ansible) - Automatic deploy bifrozt with ansible.
  - [Conpot](http://conpot.org/) - Low interactive server side Industrial Control Systems honeypot.
  - [Heralding](https://github.com/johnnykv/heralding) - Credentials catching honeypot.
  - [HoneyWRT](https://github.com/CanadianJeff/honeywrt) - Low interaction Python honeypot designed to mimic services or ports that might get targeted by attackers.
  - [Honeyd](https://github.com/provos/honeyd) - See [honeyd tools](#honeyd-tools).
  - [Honeysink](http://www.honeynet.org/node/773) - Open source network sinkhole that provides a mechanism for detection and prevention of malicious traffic on a given network.
  - [Hontel](https://github.com/stamparm/hontel) - Telnet Honeypot.
  - [KFSensor](http://www.keyfocus.net/kfsensor/) - Windows based honeypot Intrusion Detection System (IDS).
  - [LaBrea](http://labrea.sourceforge.net/labrea-info.html) - Takes over unused IP addresses, and creates virtual servers that are attractive to worms, hackers, and other denizens of the Internet.
  - [MTPot](https://github.com/Cymmetria/MTPot) - Open Source Telnet Honeypot, focused on Mirai malware.
  - [SIREN](https://github.com/blaverick62/SIREN) - Semi-Intelligent HoneyPot Network - HoneyNet Intelligent Virtual Environment.
  - [TelnetHoney](https://github.com/balte/TelnetHoney) - Simple telnet honeypot.
  - [UDPot Honeypot](https://github.com/jekil/UDPot) - Simple UDP/DNS honeypot scripts.
  - [Yet Another Fake Honeypot (YAFH)](https://github.com/fnzv/YAFH) - Simple honeypot written in Go.
  - [arctic-swallow](https://github.com/ajackal/arctic-swallow) - Low interaction honeypot.
  - [fapro](https://github.com/fofapro/fapro) - Fake Protocol Server.
  - [glutton](https://github.com/mushorg/glutton) - All eating honeypot.
  - [go-HoneyPot](https://github.com/Mojachieee/go-HoneyPot) - Honeypot server written in Go.
  - [go-emulators](https://github.com/kingtuna/go-emulators) - Honeypot Golang emulators.
  - [honeymail](https://github.com/sec51/honeymail) - SMTP honeypot written in Golang.
  - [honeytrap](https://github.com/tillmannw/honeytrap) - Low-interaction honeypot and network security tool written to catch attacks against TCP and UDP services.
  - [imap-honey](https://github.com/yvesago/imap-honey) - IMAP honeypot written in Golang.
  - [mwcollectd](https://www.openhub.net/p/mwcollectd) - Versatile malware collection daemon, uniting the best features of nepenthes and honeytrap.
  - [potd](https://github.com/lnslbrty/potd) - Highly scalable low- to medium-interaction SSH/TCP honeypot designed for OpenWrt/IoT devices leveraging several Linux kernel features, such as namespaces, seccomp and thread capabilities.
  - [portlurker](https://github.com/bartnv/portlurker) - Port listener in Rust with protocol guessing and safe string display.
  - [slipm-honeypot](https://github.com/rshipp/slipm-honeypot) - Simple low-interaction port monitoring honeypot.
  - [telnet-iot-honeypot](https://github.com/Phype/telnet-iot-honeypot) - Python telnet honeypot for catching botnet binaries.
  - [telnetlogger](https://github.com/robertdavidgraham/telnetlogger) - Telnet honeypot designed to track the Mirai botnet.
  - [vnclowpot](https://github.com/magisterquis/vnclowpot) - Low interaction VNC honeypot.

- IDS signature generation

  - [Honeycomb](http://www.icir.org/christian/honeycomb/) - Automated signature creation using honeypots.

- Data Collection / Data Sharing

  - [HPfriends](http://hpfriends.honeycloud.net/#/home) - Honeypot data-sharing platform.
    - [hpfriends - real-time social data-sharing](https://heipei.io/sigint-hpfriends/) - Presentation about HPFriends feed system
  - [HPFeeds](https://github.com/rep/hpfeeds/) - Lightweight authenticated publish-subscribe protocol.

- Client

  - [CWSandbox / GFI Sandbox](https://www.gfi.com/products-and-solutions/all-products)
  - [Capture-HPC-Linux](https://redmine.honeynet.org/projects/linux-capture-hpc/wiki)
  - [Capture-HPC-NG](https://github.com/CERT-Polska/HSN-Capture-HPC-NG)
  - [Capture-HPC](https://projects.honeynet.org/capture-hpc) - High interaction client honeypot (also called honeyclient).
  - [HoneyBOT](http://www.atomicsoftwaresolutions.com/)
  - [HoneyC](https://projects.honeynet.org/honeyc)
  - [HoneySpider Network](https://github.com/CERT-Polska/hsn2-bundle) - Highly-scalable system integrating multiple client honeypots to detect malicious websites.
  - [HoneyWeb](https://code.google.com/archive/p/gsoc-honeyweb/) - Web interface created to manage and remotely share Honeyclients resources.
  - [Jsunpack-n](https://github.com/urule99/jsunpack-n)
  - [MonkeySpider](http://monkeyspider.sourceforge.net)
  - [PhoneyC](https://github.com/honeynet/phoneyc) - Python honeyclient (later replaced by Thug).
  - [Pwnypot](https://github.com/shjalayeri/pwnypot) - High Interaction Client Honeypot.
  - [Rumal](https://github.com/thugs-rumal/) - Thug's Rumāl: a Thug's dress and weapon.
  - [Shelia](https://www.cs.vu.nl/~herbertb/misc/shelia/) - Client-side honeypot for attack detection.
  - [Thug](https://buffer.github.io/thug/) - Python-based low-interaction honeyclient.
  - [Thug Distributed Task Queuing](https://thug-distributed.readthedocs.io/en/latest/index.html)
  - [Trigona](https://www.honeynet.org/project/Trigona)
  - [URLQuery](https://urlquery.net/)
  - [YALIH (Yet Another Low Interaction Honeyclient)](https://github.com/Masood-M/yalih) - Low-interaction client honeypot designed to detect malicious websites through signature, anomaly, and pattern matching techniques.

- Honeypot

  - [Deception Toolkit](http://www.all.net/dtk/dtk.html)
  - [IMHoneypot](https://github.com/mushorg/imhoneypot)

- Hybrid low/high interaction honeypot

  - [HoneyBrid](http://honeybrid.sourceforge.net)

- SSH Honeypots

  - [Blacknet](https://github.com/morian/blacknet) - Multi-head SSH honeypot system.
  - [Cowrie](https://github.com/cowrie/cowrie) - Cowrie SSH Honeypot (based on kippo).
  - [DShield docker](https://github.com/xme/dshield-docker) - Docker container running cowrie with DShield output enabled.
  - [endlessh](https://github.com/skeeto/endlessh) - SSH tarpit that slowly sends an endless banner. ([docker image](https://hub.docker.com/r/linuxserver/endlessh))
  - [HonSSH](https://github.com/tnich/honssh) - Logs all SSH communications between a client and server.
  - [HUDINX](https://github.com/Cryptix720/HUDINX) - Tiny interaction SSH honeypot engineered in Python to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.
  - [Kippo](https://github.com/desaster/kippo) - Medium interaction SSH honeypot.
  - [Kippo_JunOS](https://github.com/gregcmartin/Kippo_JunOS) - Kippo configured to be a backdoored netscreen.
  - [Kojoney2](https://github.com/madirish/kojoney2) - Low interaction SSH honeypot written in Python and based on Kojoney by Jose Antonio Coret.
  - [Kojoney](http://kojoney.sourceforge.net/) - Python-based Low interaction honeypot that emulates an SSH server implemented with Twisted Conch.
  - [Longitudinal Analysis of SSH Cowrie Honeypot Logs](https://github.com/deroux/longitudinal-analysis-cowrie) - Python based command line tool to analyze cowrie logs over time.
  - [LongTail Log Analysis @ Marist College](http://longtail.it.marist.edu/honey/) - Analyzed SSH honeypot logs.
  - [Malbait](https://github.com/batchmcnulty/Malbait) - Simple TCP/UDP honeypot implemented in Perl.
  - [MockSSH](https://github.com/ncouture/MockSSH) - Mock an SSH server and define all commands it supports (Python, Twisted).
  - [cowrie2neo](https://github.com/xlfe/cowrie2neo) - Parse cowrie honeypot logs into a neo4j database.
  - [go-sshoney](https://github.com/ashmckenzie/go-sshoney) - SSH Honeypot.
  - [go0r](https://github.com/fzerorubigd/go0r) - Simple ssh honeypot in Golang.
  - [gohoney](https://github.com/PaulMaddox/gohoney) - SSH honeypot written in Go.
  - [hived](https://github.com/sahilm/hived) - Golang-based honeypot.
  - [hnypots-agent)](https://github.com/joshrendek/hnypots-agent) - SSH Server in Go that logs username and password combinations.
  - [honeypot.go](https://github.com/mdp/honeypot.go) - SSH Honeypot written in Go.
  - [honeyssh](https://github.com/ppacher/honeyssh) - Credential dumping SSH honeypot with statistics.
  - [hornet](https://github.com/czardoz/hornet) - Medium interaction SSH honeypot that supports multiple virtual hosts.
  - [ssh-auth-logger](https://github.com/JustinAzoff/ssh-auth-logger) - Low/zero interaction SSH authentication logging honeypot.
  - [ssh-honeypot](https://github.com/droberson/ssh-honeypot) - Fake sshd that logs IP addresses, usernames, and passwords.
  - [ssh-honeypot](https://github.com/amv42/sshd-honeypot) - Modified version of the OpenSSH deamon that forwards commands to Cowrie where all commands are interpreted and returned.
  - [ssh-honeypotd](https://github.com/sjinks/ssh-honeypotd) - Low-interaction SSH honeypot written in C.
  - [sshForShits](https://github.com/traetox/sshForShits) - Framework for a high interaction SSH honeypot.
  - [sshesame](https://github.com/jaksi/sshesame) - Fake SSH server that lets everyone in and logs their activity.
  - [sshhipot](https://github.com/magisterquis/sshhipot) - High-interaction MitM SSH honeypot.
  - [sshlowpot](https://github.com/magisterquis/sshlowpot) - Yet another no-frills low-interaction SSH honeypot in Go.
  - [sshsyrup](https://github.com/mkishere/sshsyrup) - Simple SSH Honeypot with features to capture terminal activity and upload to asciinema.org.
  - [twisted-honeypots](https://github.com/lanjelot/twisted-honeypots) - SSH, FTP and Telnet honeypots based on Twisted.

- Distributed sensor project

  - [DShield Web Honeypot Project](https://sites.google.com/site/webhoneypotsite/)

- Network traffic redirector

  - [Honeywall](https://projects.honeynet.org/honeywall/)

- Honeypot Distribution with mixed content

  - [HoneyDrive](https://bruteforcelab.com/honeydrive)

- Honeypot sensor

  - [Honeeepi](https://redmine.honeynet.org/projects/honeeepi/wiki) - Honeypot sensor on a Raspberry Pi based on a customized Raspbian OS.

- File carving

  - [TestDisk & PhotoRec](https://www.cgsecurity.org/)

- Behavioral analysis tool for win32

  - [Capture BAT](https://www.honeynet.org/node/315)

- Live CD

  - [DAVIX](https://www.secviz.org/node/89) - The DAVIX Live CD.

- Spamtrap

  - [Mail::SMTP::Honeypot](https://metacpan.org/pod/release/MIKER/Mail-SMTP-Honeypot-0.11/Honeypot.pm) - Perl module that appears to provide the functionality of a standard SMTP server.
  - [Mailoney](https://github.com/awhitehatter/mailoney) - SMTP honeypot, Open Relay, Cred Harvester written in python.
  - [SendMeSpamIDS.py](https://github.com/johestephan/VerySimpleHoneypot) - Simple SMTP fetch all IDS and analyzer.
  - [Shiva](https://github.com/shiva-spampot/shiva) - Spam Honeypot with Intelligent Virtual Analyzer.
    - [Shiva The Spam Honeypot Tips And Tricks For Getting It Up And Running](https://www.pentestpartners.com/security-blog/shiva-the-spam-honeypot-tips-and-tricks-for-getting-it-up-and-running/)
  - [SMTPLLMPot](https://github.com/referefref/SMTPLLMPot) - A super simple SMTP Honeypot built using GPT3.5
  - [SpamHAT](https://github.com/miguelraulb/spamhat) - Spam Honeypot Tool.
  - [Spamhole](http://www.spamhole.net/)
  - [honeypot](https://github.com/jadb/honeypot) - The Project Honey Pot un-official PHP SDK.
  - [spamd](http://man.openbsd.org/cgi-bin/man.cgi?query=spamd%26apropos=0%26sektion=0%26manpath=OpenBSD+Current%26arch=i386%26format=html)

- Commercial honeynet

  - [Cymmetria Mazerunner](ttps://cymmetria.com/products/mazerunner/) - Leads attackers away from real targets and creates a footprint of the attack.

- Dockerized Low Interaction packaging

  - [Docker honeynet](https://github.com/sreinhardt/Docker-Honeynet) - Several Honeynet tools set up for Docker containers.
  - [Dockerized Thug](https://hub.docker.com/r/honeynet/thug/) - Dockerized [Thug](https://github.com/buffer/thug) to analyze malicious web content.
  - [Dockerpot](https://github.com/mrschyte/dockerpot) - Docker based honeypot.
  - [Manuka](https://github.com/andrewmichaelsmith/manuka) - Docker based honeypot (Dionaea and Kippo).
  - [honey_ports](https://github.com/run41/honey_ports) - Very simple but effective docker deployed honeypot to detect port scanning in your environment.
  - [mhn-core-docker](https://github.com/MattCarothers/mhn-core-docker) - Core elements of the Modern Honey Network implemented in Docker.

- IOT Honeypot

  - [HoneyThing](https://github.com/omererdem/honeything) - TR-069 Honeypot.
  - [Kako](https://github.com/darkarnium/kako) - Honeypots for a number of well known and deployed embedded device vulnerabilities.

- Honeytokens
  - [CanaryTokens](https://github.com/thinkst/canarytokens) - Self-hostable honeytoken generator and reporting dashboard; demo version available at [CanaryTokens.org](https://canarytokens.org/generate).
  - [Honeybits](https://github.com/0x4D31/honeybits) - Simple tool designed to enhance the effectiveness of your traps by spreading breadcrumbs and honeytokens across your production servers and workstations to lure the attacker toward your honeypots.
  - [Honeyλ (HoneyLambda)](https://github.com/0x4D31/honeylambda) - Simple, serverless application designed to create and monitor URL honeytokens, on top of AWS Lambda and Amazon API Gateway.
  - [dcept](https://github.com/secureworks/dcept) - Tool for deploying and detecting use of Active Directory honeytokens.
  - [honeyku](https://github.com/0x4D31/honeyku) - Heroku-based web honeypot that can be used to create and monitor fake HTTP endpoints (i.e. honeytokens).


## Network and Artifact Analysis

- Sandbox

  - [Argos](http://www.few.vu.nl/argos/) - Emulator for capturing zero-day attacks.
  - [COMODO automated sandbox](https://help.comodo.com/topic-72-1-451-4768-.html)
  - [Cuckoo](https://cuckoosandbox.org/) - Leading open source automated malware analysis system.
  - [Pylibemu](https://github.com/buffer/pylibemu) - Libemu Cython wrapper.
  - [RFISandbox](https://monkey.org/~jose/software/rfi-sandbox/) - PHP 5.x script sandbox built on top of [funcall](https://pecl.php.net/package/funcall).
  - [dorothy2](https://github.com/m4rco-/dorothy2) - Malware/botnet analysis framework written in Ruby.
  - [imalse](https://github.com/hbhzwj/imalse) - Integrated MALware Simulator and Emulator.
  - [libemu](https://github.com/buffer/libemu) - Shellcode emulation library, useful for shellcode detection.

## Guides

- [T-Pot: A Multi-Honeypot Platform](https://dtag-dev-sec.github.io/mediator/feature/2015/03/17/concept.html)
- [Honeypot (Dionaea and kippo) setup script](https://github.com/andrewmichaelsmith/honeypot-setup-script/)

- Deployment

  - [Dionaea and EC2 in 20 Minutes](http://andrewmichaelsmith.com/2012/03/dionaea-honeypot-on-ec2-in-20-minutes/) - Tutorial on setting up Dionaea on an EC2 instance.
  - [Using a Raspberry Pi honeypot to contribute data to DShield/ISC](https://isc.sans.edu/diary/22680) - The Raspberry Pi based system will allow us to maintain one code base that will make it easier to collect rich logs beyond firewall logs.
  - [honeypotpi](https://github.com/free5ty1e/honeypotpi) - Script for turning a Raspberry Pi into a HoneyPot Pi.

- Research Papers

  - [Honeypot research papers](https://github.com/shbhmsingh72/Honeypot-Research-Papers) - PDFs of research papers on honeypots.
  - [vEYE](https://link.springer.com/article/10.1007%2Fs10115-008-0137-3) - Behavioral footprinting for self-propagating worm detection and profiling.
