# Web Vulnerability Methodology: Injection Flaws

Methodologies for discovering and validating SQL Injection, Server-Side Template Injection (SSTI), and Command Injection.

---

## 1. SQL Injection (SQLi)
- **Vectors**: Test URL query parameters, POST body JSON/form fields, and HTTP headers (`User-Agent`, `X-Forwarded-For`).
- **Boolean Probing**:
  - Compare response status, length, and body content for `' OR 1=1--` vs `' OR 1=2--`.
- **Error-Based**:
  - Inject syntax breakers (`'`, `"`, `\`, `)`) to elicit backend database syntax errors.
- **Time-Based Blind**:
  - `pg_sleep(5)`, `WAITFOR DELAY '0:0:5'`, `AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)`.
  - Confirm timing differences over at least 2 distinct requests.
- **Safety**: NEVER dump user credentials during scanning. Limit benign verification to `SELECT version()` or `user()`.

---

## 2. Server-Side Template Injection (SSTI)
- **Polyglot & Engine Probing**:
  - Jinja2 / Twig: `{{7*7}}` $\to$ `49`
  - Spring Expression Language (SpEL): `${7*7}` $\to$ `49`
  - Ruby / ERB: `<%= 7*7 %>` $\to$ `49`
  - Node.js Pug: `#{7*7}` $\to$ `49`
- **Confirmation**: Verify that mathematical evaluation occurs on the server and is reflected in the rendered response.

---

## 3. Command Injection
- **Separators**: `;`, `|`, `||`, `&`, `&&`, `` ` ``, `$()`.
- **Benign Observer Payloads**:
  - `id`, `whoami`, `uname -a`.
  - Time delays: `sleep 5`.
- **Safety**: Do not alter files, download external scripts, or spawn persistent listeners without explicit HITL approval.
