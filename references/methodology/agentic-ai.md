# Methodology: agentic-ai

Source: [PentestingEverything/A2A Security Assessment](https://github.com/m14r41/PentestingEverything/tree/main/A2A%20Security%20Assessment)

---

Agent-to-Agent (A2A) is an open protocol for autonomous agents to discover and delegate work to each other across organisational boundaries. Where [MCP](https://github.com/m14r41/PentestingEverything/tree/main/MCP%20Security%20Assessment) connects an agent to its *tools*, A2A connects an agent to *other agents*. That shifts the trust problem: a target agent now takes instructions and tasks from remote agents it did not author, over the network.

A2A Security Assessment is the process of testing an agent that exposes or consumes an A2A interface: how it publishes its identity (the Agent Card), how it authenticates and authorises callers, how it scopes task data, and how it handles the webhooks used for push notifications. Only test agents you are authorised to assess.

## Protocol at a glance

| Concept | Meaning |
| --- | --- |
| **Agent Card** | A JSON document describing an agent: its interfaces, capabilities, skills, `securitySchemes`, and optional signatures. Usually served at `https://{domain}/.well-known/agent-card.json`. |
| **Skill** | A capability the agent advertises (id, name, description, tags, examples). The description and examples are model-facing text. |
| **Task** | A unit of work created by `SendMessage`; has an id, a context id, a state, and history. |
| **Push notification** | An agent-to-webhook callback that reports task updates to a client-supplied URL. |
| **Extended Agent Card** | A richer card returned only to authenticated callers. |

The default binding is JSON-RPC 2.0 over HTTPS. Core methods use PascalCase: `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`, the `*TaskPushNotificationConfig` methods, and `GetExtendedAgentCard`. Service parameters such as `A2A-Version` travel as HTTP headers.

## 1. Recon: fetch and read the Agent Card

The Agent Card is the map of the attack surface. Fetch it from the well-known URI:

```bash
curl -sS https://target-agent.example.com/.well-known/agent-card.json | jq .
```

Review:

- **`supportedInterfaces`** — the URLs and bindings (`JSONRPC`, `GRPC`, `HTTP+JSON`). Each is a testable endpoint.
- **`securitySchemes` and `securityRequirements`** — how callers are meant to authenticate (API key, HTTP auth, OAuth2, OpenID Connect, mutual TLS). Note what is required so you can test what happens without it.
- **`skills`** — `description` and `examples` are fed to the model; treat them as injection-relevant text just as with MCP tool descriptions.
- **`cap

---

