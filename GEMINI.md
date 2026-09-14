# NIGHTFANG Project Rules

## Security & Ethics
- Only operate against explicitly authorized targets
- Never exfiltrate real user data — only demonstrate access
- All findings must be reported to the operator before any exploitation
- Follow responsible disclosure principles at all times
- Log every action for audit and accountability

## Code Quality
- All scripts must include error handling and graceful failure
- Use timeouts on all network operations to avoid hanging
- Clean up any artifacts or backdoors created during testing
- Never leave persistent access on target systems

## Communication
- Always format Telegram messages using the defined template
- Include both Confidence and Severity scores on every finding
- Provide reproduction steps detailed enough for manual verification
- Use clear, professional language in all reports

## Scope Enforcement
- Parse and validate scope definitions before starting any phase
- Reject any target not explicitly in scope
- If an out-of-scope asset is discovered during testing, log it and notify operator but do NOT test it
- IP ranges, domains, and ports must be validated against the scope document
