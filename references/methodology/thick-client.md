# Methodology: thick-client

Source: [PentestingEverything/Thick Client Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/Thick%20Client%20Pentesting)

---

# Thick Client Penetration Testing

Thick client pentesting is the testing of desktop and rich applications (for example Windows, Java, or .NET apps) to find security problems. It is not only about the server. We also look at how the app stores data on the machine, how it talks to the server, and whether someone could tamper with it or reverse engineer it.

> Stay updated with the official OWASP guide: https://owasp.org/www-project-desktop-app-security-top-10/

---

## Table of Contents

1. [What Is a Thick Client](#what-is-a-thick-client)
2. [Thin Client vs Thick Client](#thin-client-vs-thick-client)
3. [Two-Tier vs Three-Tier Applications](#two-tier-vs-three-tier-applications)
4. [Common Programming Languages](#common-programming-languages)
5. [Common Obfuscation and Deobfuscation](#common-obfuscation-and-deobfuscation)
6. [Common Vulnerabilities](#common-vulnerabilities)
7. [Common Tools](#common-tools)
8. [Testing Methodology](#testing-methodology)
9. [Vulnerability Checklist](#vulnerability-checklist)
10. [Deep Dive Guides](#deep-dive-guides)
11. [Resources](#resources)
12. [Checklists and GitHub References](#checklists-and-github-references)
13. [Vulnerable Practice Applications](#vulnerable-practice-applications)
14. [Credits](#credits)

---

## What Is a Thick Client

A thick client is an application that is installed locally on a user's desktop or laptop. These apps are full-featured and can often run on their own without a constant internet connection, unlike web apps that need the browser and server at all times.

Examples of thick clients:

1. Games such as Call of Duty and Uncharted
2. Web browsers
3. Music players
4. Video and chat tools such as Teams, Zoom, and Slack

Because a large part of the app runs on hardware the user controls, the local attack surface is larger than a typical web app. You can inspect the binary, read local storage, watch memory, and change runtime behavior.

---

## Thin Client vs Thick Client

| S.N | Basis | Thin Client | Thick Client |
| --- | --- | --- | --- |
| 1 | Basic | A lightweight client that relies on the host or server for most resources | Relies less on the server and provides rich local functionality |
| 2 | Data store | Data is stored on the server | Data is stored locally |
| 3 | Network | Needs a fast and stable network connection | Can work with a slow connection |
| 4 | Offline use | No offline use | Offline use is possible |
| 5 | Deployment | Easier to deploy and update | Deployment and updates 

---

