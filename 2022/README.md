# macOS Security Research 2022

# Janaury

## Blog Posts
* [A Threat Hunter’s Guide to the Mac’s Most Prevalent Adware Infections 2022](https://www.sentinelone.com/labs/a-threat-hunters-guide-to-the-macs-most-prevalent-adware-infections-2022/) - Phil Stokes
* [DazzleSpy Mac Malware Used in Targeted Attacks](https://www.intego.com/mac-security-blog/dazzlespy-mac-malware-used-in-targeted-attacks/) - Josh Long (Intego)
  * Summary based on others analysis, contains IoCs
* [Hiding malware in Docker Desktop's virtual machine](https://community.atlassian.com/t5/Trust-Security-articles/Hiding-malware-in-Docker-Desktop-s-virtual-machine/ba-p/1924743)

## Malware
* [The Mac Malware of 2021](https://objective-see.org/blog/blog_0x6B.html) - Patrick Wardle
* SysJoker
  * [SysJoker](https://objective-see.com/blog/blog_0x6C.html) - Patrick Wardle
  * [New SysJoker Backdoor Targets Windows, Linux, and macOS](https://www.intezer.com/blog/malware-analysis/new-backdoor-sysjoker/) - Intezer
* DazzleSpy (osxrk)
  * [Watering hole deploys new macOS malware, DazzleSpy, in Asia](https://www.welivesecurity.com/2022/01/25/watering-hole-deploys-new-macos-malware-dazzlespy-asia/) - ESET
    * ESET [Tweet Thread](https://twitter.com/ESETresearch/status/1485923814332637190)
  * [Analyzing OSX.DazzleSpy](https://objective-see.com/blog/blog_0x6D.html) - Patrick Wardle
  * DazzleSpy (osxrk) is related to the malware Google TAG discovered in November 2021 which they, and Sentinel One, named MACMA/ macOS.Macma
    * [Analyzing a watering hole campaign using macOS exploits](https://blog.google/threat-analysis-group/analyzing-watering-hole-campaign-using-macos-exploits/) by Erye Hernandez
    * [Infect If Needed | A Deeper Dive Into Targeted Backdoor macOS.Macma](https://www.sentinelone.com/labs/infect-if-needed-a-deeper-dive-into-targeted-backdoor-macos-macma/) by Phil Stokes

## Vulnerabilities & Exploits
* [Microsoft OneDrive for macOS Local Privilege Escalation](https://www.offensive-security.com/offsec/microsoft-onedrive-macos-local-privesc/) - Csaba Fitzl
* [New macOS vulnerability, “powerdir,” could lead to unauthorized user data access](https://www.microsoft.com/security/blog/2022/01/10/new-macos-vulnerability-powerdir-could-lead-to-unauthorized-user-data-access/) - Microsoft Security


---


# February

## Malware
* [The evolution of a Mac trojan: UpdateAgent’s progression](https://www.microsoft.com/en-us/security/blog/2022/02/02/the-evolution-of-a-mac-trojan-updateagents-progression/)

## Offensive
* [Querying Spotlight APIs With JXA](https://cedowens.medium.com/querying-spotlight-apis-with-jxa-3ae4bb9af3b4) - Cedric Owens
* [Give Me Some (macOS) Context…](https://cedowens.medium.com/give-me-some-macos-context-c13aecbd4c5b) - Cedric Owens


---


# March

## Blog Posts
* [Beyond the good ol' LaunchAgents - 29 - amstoold](https://theevilbit.github.io/beyond/beyond_0029/) - Csaba Fitzl
* [How a macOS bug could have allowed for a serious phishing attack against users](https://rambo.codes/posts/2022-03-15-how-a-macos-bug-could-have-allowed-for-a-serious-phishing-attack-against-users) - Guilherme Rambo

## Malware
* [Storm Cloud on the Horizon: GIMMICK Malware Strikes at macOS](https://www.volexity.com/blog/2022/03/22/storm-cloud-on-the-horizon-gimmick-malware-strikes-at-macos/) - Damien Cash, Steven Adair & Thomas Lancaster (Volexity)

## Offensive
* [Extended Attributes and TCC on macOS](https://medium.com/@slyd0g/extended-attributes-and-tcc-on-macos-a535878f2c8d) - Justin Bui
* [macOS Red Teaming: Bypass TCC with old apps](https://wojciechregula.blog/post/macos-red-teaming-bypass-tcc-with-old-apps/) - Wojciech Reguła

## Vulnerabilities & Exploits
* [Technical Advisory – Apple macOS XAR – Arbitrary File Write (CVE-2022-22582)](https://research.nccgroup.com/2022/03/15/technical-advisory-apple-macos-xar-arbitrary-file-write-cve-2022-22582/) - Rich Warren
* CVE-2022-22616
  * [Jamf Threat Labs identifies Safari vulnerability allowing for Gatekeeper bypass](https://www.jamf.com/blog/jamf-threat-labs-safari-vuln-gatekeeper-bypass/)
  * [CVE-2022-22616: Simple way to bypass GateKeeper, hidden for years](https://jhftss.github.io/CVE-2022-22616-Gatekeeper-Bypass/) - Mickey Jin

## Conference Talks
* [Learning macOS Security by Finding Vulns](https://www.youtube.com/watch?v=jBvE0kciSx8) - Jonathan Bar Or (BlueHat IL)


---


# April

## Blog Posts
* [Remotely Dumping Chrome Cookies...Revisited](https://web.archive.org/web/20220404224341/https://cedowens.medium.com/remotely-dumping-chrome-cookies-revisited-b25343257209) - Cedric Owens 
* [Understanding and Defending Against Reflective Code Loading on macOS](https://slyd0g.medium.com/understanding-and-defending-against-reflective-code-loading-on-macos-e2e83211e48f) - Justin Bui 
* [Expanding Apple Ecosystem Access with Open Source, Multi Platform Code Signing](https://gregoryszorc.com/blog/2022/04/25/expanding-apple-ecosystem-access-with-open-source,-multi-platform-code-signing/) - Gregory Szorc

## Vulnerabilities & Exploits
* [MacOS SUHelper Root Privilege Escalation Vulnerability: A Deep Dive Into CVE-2022-22639](https://www.trendmicro.com/en_us/research/22/d/macos-suhelper-root-privilege-escalation-vulnerability-a-deep-di.html) - Mickey Jin
  * CVE-2022-22639
* [Using Data Memory-Dependent Prefetchers to Leak Data at Rest](https://www.prefetchers.info/) - UIUC, UW, & Tel Aviv University
  * “We present a new type of microarchitectural attack that leaks data at rest: data that is never read into the core architecturally. This attack technique, Augury, leverages a novel microarchitectural optimisation present in Apple Silicon: a Data Memory-Dependent Prefetcher (DMP).“

## Tweets
* https://twitter.com/th3_protoCOL/status/1519362330244444160
  * ChoziosiLoader targeting macOS users 
* https://twitter.com/coolestcatiknow/status/1519375315251961863
  * List of contributions to macOS ATT&CK v11


---


# May

## Blog Posts
* [LIEF - Mach-O Support Enhancements](https://lief-project.github.io/blog/2022-05-08-macho/) - Romain Thomas 
* [Taking ESF For A(nother) Spin](https://cedowens.medium.com/taking-esf-for-a-nother-spin-6e1e6acd1b74) - Cedric Owens

## Malware
https://googleprojectzero.github.io/0days-in-the-wild/0day-RCAs/2022/CVE-2022-22675.html - Natalie Silvanovich
https://blog.ret2.io/2022/05/19/pwn2own-2021-parallels-desktop-exploit/ - Jack Dates macOS Vulnerabilities 

## Conference Talks
* [macOS Vulnerabilities Hiding in Plain Sight](https://www.youtube.com/watch?v=Nvpo-kP6C9s) - Csaba Fitzl (Black Hat Asia)
  * [Slides](https://i.blackhat.com/Asia-22/Friday-Materials/AS-22-Fitzl-macOS-vulnerabilities-hiding-in-plain-sight.pdf)
  * [Whitepaper](https://i.blackhat.com/Asia-22/Friday-Materials/AS-22-Fitzl-macOS-vulnerabilities-hiding-in-plain-sight-wp.pdf)

## Vulnerabilities & Exploits
* [Analyzing a Pirrit adware installer](https://forensicitguy.github.io/analyzing-pirrit-adware-installer/) - Tony Lambert 
* [From The DPRK With Love](https://objective-see.org/blog/blog_0x6E.html) - Patrick Wardle 
* [From the Front Lines | Unsigned macOS oRAT Malware Gambles For The Win](https://www.sentinelone.com/blog/from-the-front-lines-unsigned-macos-orat-malware-gambles-for-the-win/) - Phil Stokes
* [UpdateAgent Adapts Again](https://www.jamf.com/blog/updateagent-adapts-again/) - Jaron Bradley, Stuart Ashenbrenner & Matt Benyo
  * Updated notes/ IOCs from June 2nd [UpdateAgent - GolangVersion](https://gist.github.com/sysopfb/19abb48672e940e778ec591c5028230c)


---


# June

## Blog Posts
* [AMFI Launch Constraints - First Quick Look](https://theevilbit.github.io/posts/amfi_launch_constraints/) - Csaba Fitzl 
* [Apple’s macOS Ventura | 7 New Security Changes to Be Aware Of](https://www.sentinelone.com/blog/apples-macos-ventura-7-new-security-changes-to-be-aware-of/) - Phil Stokes 
* [CrowdStrike Uncovers New MacOS Browser Hijacking Campaign](https://www.crowdstrike.com/blog/how-crowdstrike-uncovered-a-new-macos-browser-hijacking-campaign/) - CrowdStrike 
* [New Security and Privacy Features in macOS Ventura, iOS 16, and iPadOS 16](https://www.intego.com/mac-security-blog/new-security-and-privacy-features-in-macos-ventura-ios-16-and-ipados-16/) - Intego
* [Exploiting Intel Graphics Kernel Extensions on macOS](https://blog.ret2.io/2022/06/29/pwn2own-2021-safari-sandbox-intel-graphics-exploit/) - Jack Dates

## Conference Talks
* [10 macOS persistence techniques](https://youtu.be/nSykVNZLeOc?t=8343) - Csaba Fitzl (Security Fest)
  * [Slides](https://www.slideshare.net/CsabaFitzl/securityfest22fitzlbeyondpdf)
* [10 macOS Persistence Techniques](https://www.youtube.com/watch?v=qySBuk7Ww7Q) - Csaba Fitzl (MacDevOpsYVR)
* [macOS Vulnerabilities Hiding in Plain Sight](https://www.slideshare.net/CsabaFitzl/macos-vulnerabilities-hiding-in-plain-sight) - Csaba Fitzl (TROOPERS2022) (Slides)

## Vulnerabilities & Exploits
* [PACMAN](https://pacmanattack.com)
  * [The PACMAN Attack: Breaking PAC on Apple M1 with Hardware Attacks](https://www.youtube.com/watch?v=WRNZhP4CVgE)
## Other
* [macOS Ventura and OpenCore Legacy Patcher Support](https://github.com/dortania/OpenCore-Legacy-Patcher/issues/998)


---


# July

## Blog Posts
* [iBoot: A New Era](https://tjkr0wn.github.io//new_era_writeup/PART1) - tjkr0wn

## Malware
* [New macOS ‘covid’ Malware Masquerades as Apple, Wears Face of APT](https://www.sentinelone.com/blog/from-the-front-lines-new-macos-covid-malware-masquerades-as-apple-wears-face-of-apt/) - Phil Stokes 
* [ChromeLoader: New Stubborn Malware Campaign](https://unit42.paloaltonetworks.com/chromeloader-malware/) - Palo Alto Networks Unit 42
  * [macOS section](https://unit42.paloaltonetworks.com/chromeloader-malware/#post-123828-_mpyacggxtibk)
* [I see what you did there: A look at the CloudMensis macOS spyware](https://www.welivesecurity.com/2022/07/19/i-see-what-you-did-there-look-cloudmensis-macos-spyware/) - Marc-Etienne M.Léveillé
  * [ESET Tweet Thread](https://twitter.com/ESETresearch/status/1549329017853067264)
## Vulerabilities
* [Uncovering a macOS App Sandbox escape vulnerability: A deep dive into CVE-2022-26706](https://www.microsoft.com/security/blog/2022/07/13/uncovering-a-macos-app-sandbox-escape-vulnerability-a-deep-dive-into-cve-2022-26706/) - Defender Research Team
  * CVE-2022-26706 

## Offesnsive
* [macOS Red Teaming: Apple Dev-ID signed Java environment](https://wojciechregula.blog/post/macos-red-teaming-apple-signed-java/) - Wojciech Regua

## Tweets
* https://twitter.com/philofishal/status/1543562218985472001
  * Adload Go variants
* https://twitter.com/patrickwardle/status/1547967373264560131
  * NSCreateObjectFileImageFromMemory now writes binary to disk before exec
* https://twitter.com/esetresearch/status/1547943014860894210
  * “fake Salesforce update as a lure to deploy the Sliver malware for macOS“
  * Related to the above SentinelOne “From the Front Lines“ post 
* https://twitter.com/zhuowei/status/1550324794830344195
  * macOS 12.5 App Store Sandbox LC_DYLD_ENVIRONMENT check