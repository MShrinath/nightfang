# Methodology: ai-llm

Source: [PentestingEverything/LLM Security Assessment](https://github.com/m14r41/PentestingEverything/tree/main/LLM%20Security%20Assessment)

---

LLM pentesting (Large Language Model penetration testing) is the process of testing an AI language model to find weaknesses in its behavior, safety, and reliability.

It involves checking how the model responds to different inputs to understand whether it can be misled, produce incorrect or unsafe outputs, or fail to follow intended rules. The goal is to improve the model’s security, accuracy, and robustness before real-world use.

## OWASP Top 10

https://genai.owasp.org/llm-top-10/

## LLM Basics

| **Concept**                     | **Meaning**                                                                               | **Simple Example**                                                                   |
| ------------------------------- | ----------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| **Model**                       | The AI system that understands input and generates responses based on patterns it learned | Think of it like a super advanced autocomplete that can also write essays, solve problems, or code |
| **Prompt**                      | The instruction or question you give to the AI                                            | “Explain photosynthesis like I’m 10 years old”                                                     |
| **Context Window**              | How much conversation text the AI can keep in mind at once                                | If you chat too long, the AI may forget what you said at the beginning                             |
| **Tokens**                      | Small chunks of text the AI reads (not always full words)                                 | “ChatGPT is great” becomes pieces like “Chat”, “GPT”, “is”, “great”                                |
| **System Message**              | Hidden rules that control how the AI should behave                                        | “Be helpful, safe, and don’t give harmful instructions” (you don’t normally see this)              |
| **Developer Message**           | App-level instructions that shape how the AI behaves in a specific app                    | A chatbot app saying: “Keep answers short and formal”                                              |
| **User Message**                | What you directly type to the AI                                                          | “What is machine learning?”                      

---

