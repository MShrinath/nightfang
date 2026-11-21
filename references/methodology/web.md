# Methodology: web

Source: [PentestingEverything/Web Application Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/Web%20Application%20Pentesting)

---

Welcome to the Web Application Penetration Testing repository. You will get help with OWASP standard references, as well as common test cases that get performed in real life i.e day to day in company.

> OWASP 2025 Top 10 : https://owasp.org/Top10/2025/

> If you are a beginner, please follow the OWASP practical guide .


 | S.N | Topic                                    | Link |
|-----|------------------------------------------|------|
| 4.0 | Introduction and Objectives               | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/00-Introduction_and_Objectives/README) |
| 4.1 | Information Gathering                     | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/README) |
| 4.2 | Configuration and Deployment Management Testing | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/README) |
| 4.3 | Identity Management Testing               | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/03-Identity_Management_Testing/README) |
| 4.4 | Authentication Testing                    | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/04-Authentication_Testing/README) |
| 4.5 | Authorization Testing                     | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/05-Authorization_Testing/README) |
| 4.6 | Session Management Testing                | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/06-Session_Management_Testing/README) |
| 4.7 | Input Validation Testing                  | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/README) |
| 4.8 | Testing for Error Handling                | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/README) |
| 4.9 | Testing for Weak Cryptography             | [Click Here](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/README) |
| 4.10| Business Logic Testing   

---

## Vulnerability Classes Covered

| Class | Description |
|-------|-------------|
| Application Logic Flaws | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| Artibtray Cookies Flag | | **Aspect** | **Details** | |---|---| |
| Back button attack | | **Aspect** | **Details** | |---|---| |
| Broken Authentication | | **Aspect** | **Details** | |---|---| |
| BruteForce Attack | | **Aspect** | **Details** | |---|---| |
| CORS | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| CRLF | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| Captcha Bypass | | **Aspect** | **Details** | |---|---| |
| Clickjacking | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| Command Injection | | **Aspect** | **Details** | |---|---| |
| Credential Stuffing | | **Aspect** | **Details** | |---|---| |
| Cross-Site Request Forgery (CSRF) | Cross-Site Request Forgery (CSRF) is an attack that tricks a user into executing unwanted actions on a web application where they are authenticated. By exploiting the trust that a website has in the user's browser, an at |
| Deserialization Vulnerability | **Serialization** is the process of converting an object's state (such as data or a structure) into a format that can be easily stored, transmitted, or transferred, such as JSON, XML, or binary. **Deserialization** is th |
| Directory Traversal | | **Aspect**                   | **Details**                                                                                                                                          | |------------------------------|---- |
| GraphQL Injection | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| HTTP Request Smuggling | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| Host Header Injection | | **Aspect** | **Details** | |---|---| |
| IDOR | | **Aspect**                   | **Details**                                                                                                                                                   | |-------------------------- |
| Improper Error Handling | | **Aspect** | **Details** | |---|---| |
| Information Disclosure | | **Aspect** | **Details** | |---|---| |
| Insecure Object Storage | | **Aspect** | **Details** | |---|---| |
| Insufficient Security Controls | | **Aspect** | **Details** | |---|---| |
| Insufficient Transport Layer Protection | | **Aspect** | **Details** | |---|---| |
| JWT Attacks | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| Misconfigured HTTP Headers | | **Aspect** | **Details** | |---|---| |
| Open File Upload | This page covers the specific angle of upload functionality and uploaded files being exposed without proper access control. For full exploitation of upload validation flaws (web shells, extension and content-type bypasse |
| Open Redirect | | **Aspect** | **Details** | |---|---| |
| Outdate TLS Version | | **Aspect** | **Details** | |---|---| |
| Path Traversal | | **Aspect** | **Details** | |---|---| |
| Privilege Escalation | | **Aspect** | **Details** | |---|---| |
| Race Condition | | **Aspect** | **Details** | |---|---| |
| Remote Code Execution (RCE) | | **Aspect** | **Details** | |---|---| |
| SQL Injection | | **Type**                       | **Sub-Type**                  | **Description**                                                                                      | **Example Commands**                               |
| SSRF | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| Security Header Missing | | **Aspect** | **Details** | |---|---| |
| Server Misconfigurations | | **Aspect** | **Details** | |---|---| |
| Server-Side Template Injection (SSTI) | Server-Side Template Injection (SSTI) is a type of security vulnerability that occurs when user input is insecurely embedded in server-side templates, allowing an attacker to execute arbitrary code on the server. This ca |
| Session Fixation | | **Aspect** | **Details** | |---|---| |
| Unrestricted File Upload | | **Aspect** | **Details** | |---|---| |
| Unsecured API Endpoints | | **Aspect** | **Details** | |---|---| |
| Unvalidated Redirects and Forwards | | **Aspect** | **Details** | |---|---| |
| Weak Ciphers | | **Aspect** | **Details** | |---|---| |
| Web Cache Deception | | **Aspect** | **Details** | |---|---| |
| Web Cache Poisoning | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| Web LLM Prompt Injection | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| XML External Entity (XXE) | **Credit** : [muhammad-qasiim](https://www.linkedin.com/in/muhammad-qasiim?miniProfileUrn=urn%3Ali%3Afsd_profile%3AACoAAEVA94wBXb4RT7qhcp8nm3cHl0RpsUkonfk&lipi=urn%3Ali%3Apage%3Ad_flagship3_feed%3BCzKWvWaUTGqvWuMi2Np4%2B |
| XSS | | **Aspect**                   | **Details**                                                                                                                                           | |------------------------------|--- |
| tabnabbing | | **Aspect** | **Details** | |---|---| |

