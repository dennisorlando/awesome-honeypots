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
  - ~~[Shadow Daemon](https://shadowd.zecure.org/overview/introduction/) - Modular Web Application Firewall / High-Interaction Honeypot for PHP, Perl, and Python apps.~~ sito morto. Peccato, sembrava carino. 
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

- Tool to convert website to server honeypots

  - ~~[HIHAT](http://hihat.sourceforge.net/) - Transform arbitrary PHP applications into web-based high-interaction Honeypots.~~ Solo php, no bueno. 

- Honeypot for USB-spreading malware

  - ~~[Ghost-usb](https://github.com/honeynet/ghost-usb-honeypot) - Honeypot for malware that propagates via USB storage devices.~~ ~~Strapuccioso, devo mettermelo pure io. Però non è rilevante.~~ Fuck it, è solo per windows

- Low interaction honeypot

  - [Honeyperl](https://sourceforge.net/projects/honeyperl/) - Honeypot software based in Perl with plugins developed for many functions like : wingates, telnet, squid, smtp, etc.
  - [T-Pot](https://github.com/dtag-dev-sec/tpotce) - All in one honeypot appliance from telecom provider T-Mobile
  - [beelzebub](https://github.com/mariocandela/beelzebub) - A secure honeypot framework, extremely easy to configure by yaml 🚀

- Server

  - [Amun](http://amunhoney.sourceforge.net) - Vulnerability emulation honeypot.
  - ~~[Artillery](https://github.com/trustedsec/artillery/) - Open-source blue team tool designed to protect Linux and Windows operating systems through multiple methods.~~
  - ~~[Bait and Switch](http://baitnswitch.sourceforge.net) - Redirects all hostile traffic to a honeypot that is partially mirroring your production system.~~ **FIGO, ma è del 2003. Potrei aggiornarlo**
  - [Honeyd](https://github.com/provos/honeyd) - See [honeyd tools](#honeyd-tools). **La cosa del "virtual ip" è interessante, devo capire come funziona.**
  - [Honeysink](http://www.honeynet.org/node/773) - Open source network sinkhole that provides a mechanism for detection and prevention of malicious traffic on a given network.
  - [LaBrea](http://labrea.sourceforge.net/labrea-info.html) - Takes over unused IP addresses, and creates virtual servers that are attractive to worms, hackers, and other denizens of the Internet.
  - [SIREN](https://github.com/blaverick62/SIREN) - Semi-Intelligent HoneyPot Network - HoneyNet Intelligent Virtual Environment.

- Hybrid low/high interaction honeypot

  - [HoneyBrid](http://honeybrid.sourceforge.net)

- SSH Honeypots

  - ~~[Blacknet](https://github.com/morian/blacknet) - Multi-head SSH honeypot system.~~ low interaction
  - [Cowrie](https://github.com/cowrie/cowrie) - Cowrie SSH Honeypot (based on kippo).
  - ~~[endlessh](https://github.com/skeeto/endlessh) - SSH tarpit that slowly sends an endless banner. ([docker image](https://hub.docker.com/r/linuxserver/endlessh))~~ not a honeypot
  - ~~[HonSSH](https://github.com/tnich/honssh) - Logs all SSH communications between a client and server.~~ just a logger
  - ~~[HUDINX](https://github.com/Cryptix720/HUDINX) - Tiny interaction SSH honeypot engineered in Python to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.~~ dubious install, non rilevante
  - [Kippo](https://github.com/desaster/kippo) - Medium interaction SSH honeypot.
  - [Kojoney2](https://github.com/madirish/kojoney2) - Low interaction SSH honeypot written in Python and based on Kojoney by Jose Antonio Coret. **PROMISING**
  - [Malbait](https://github.com/batchmcnulty/Malbait) - Simple TCP/UDP honeypot implemented in Perl. **La cosa del fuzz e confondere l'attaccante è interessante**
  - [MockSSH](https://github.com/ncouture/MockSSH) - Mock an SSH server and define all commands it supports (Python, Twisted). **intriguing, forse è uguale a Kippo**
  - [hornet](https://github.com/czardoz/hornet) - Medium interaction SSH honeypot that supports multiple virtual hosts.
  - [ssh-honeypot](https://github.com/amv42/sshd-honeypot) - Modified version of the OpenSSH deamon that forwards commands to Cowrie where all commands are interpreted and returned. **NO FINGERPRINTING**

- Honeytokens
  - [CanaryTokens](https://github.com/thinkst/canarytokens) - Self-hostable honeytoken generator and reporting dashboard; demo version available at [CanaryTokens.org](https://canarytokens.org/generate).
  - [Honeybits](https://github.com/0x4D31/honeybits) - Simple tool designed to enhance the effectiveness of your traps by spreading breadcrumbs and honeytokens across your production servers and workstations to lure the attacker toward your honeypots.
  - [Honeyλ (HoneyLambda)](https://github.com/0x4D31/honeylambda) - Simple, serverless application designed to create and monitor URL honeytokens, on top of AWS Lambda and Amazon API Gateway.
  - [dcept](https://github.com/secureworks/dcept) - Tool for deploying and detecting use of Active Directory honeytokens.
  - ~~[honeyku](https://github.com/0x4D31/honeyku) - Heroku-based web honeypot that can be used to create and monitor fake HTTP endpoints (i*.e. honeytokens).~~ **Interessante la distinzione tra attaccanti umani e crawler / robots**

## Guides

- [T-Pot: A Multi-Honeypot Platform](https://dtag-dev-sec.github.io/mediator/feature/2015/03/17/concept.html)
- [Honeypot (Dionaea and kippo) setup script](https://github.com/andrewmichaelsmith/honeypot-setup-script/)


- Research Papers

  - [Honeypot research papers](https://github.com/shbhmsingh72/Honeypot-Research-Papers) - PDFs of research papers on honeypots.
  - [vEYE](https://link.springer.com/article/10.1007%2Fs10115-008-0137-3) - Behavioral footprinting for self-propagating worm detection and profiling.
