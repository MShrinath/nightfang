# Methodology: ai-mcp

Source: [PentestingEverything/MCP Security Assessment](https://github.com/m14r41/PentestingEverything/tree/main/MCP%20Security%20Assessment)

---

MCP Pentesting (Model Context Protocol penetration testing) is the process of testing an AI system that uses external tools (like databases, APIs, files, or web services) to find security weaknesses. It checks whether the AI can be tricked or misused when it interacts with these tools, especially through bad inputs, malicious instructions, or improper permissions.

The goal of MCP pentesting is to identify risks like data leaks, unauthorized tool access, or unsafe automated actions before real attackers can exploit them. In simple terms, it is a controlled way of trying to break or misuse an AI-tool system so its security problems can be found and fixed early.

## OWASP MCP Top 10
https://owasp.org/www-project-mcp-top-10/

# MCP (Model Context Protocol) : Basics

| **Concept**                      | **Meaning**                                                                                                  | **Example**                                                                                                                    |
| -------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------- |
| **MCP (Model Context Protocol)** | A standard protocol that lets AI applications connect to external tools and data sources in a consistent way | Like a universal “adapter” that allows AI to plug into different systems (databases, APIs, apps) without custom integration each time |
| **MCP Client**                   | The application (AI system) that sends requests using MCP                                                    | A chatbot that asks external systems for data or actions                                                                              |
| **MCP Server**                   | A service that exposes tools, data, or capabilities to the AI through MCP                                    | A server that provides tools like file search, database queries, or API access                                                        |
| **Tools**                        | Functions exposed by MCP servers that perform specific actions                                               | “search_files”, “get_weather”, “query_customer_db”                                                                                    |
| **Tool Call**              

---

