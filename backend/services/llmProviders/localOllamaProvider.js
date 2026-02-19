// backend/services/llmProviders/localOllamaProvider.js
// Diamond-tier local LLM provider for Ollama (Node 18+ compatible)

const OLLAMA_URL = process.env.OLLAMA_URL || "http://127.0.0.1:11434";
const MODEL = process.env.OLLAMA_MODEL || "llama3.1:8b";

/**
 * Calls Ollama using native Node 18+ fetch.
 * Enforces deterministic output for SOC reasoning.
 */
async function callLocalOllama(prompt) {
  if (typeof fetch !== "function") {
    throw new Error(
      "Global fetch is not available. Node 18+ is required."
    );
  }

  const res = await fetch(`${OLLAMA_URL}/api/generate`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: MODEL,
      prompt,
      stream: false,
      options: {
        temperature: 0.2,
        top_p: 0.9,
        repeat_penalty: 1.1,
      },
    }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Ollama error ${res.status}: ${text}`);
  }

  const data = await res.json();

  if (!data || typeof data.response !== "string") {
    throw new Error("Ollama returned malformed response");
  }

  return data.response.trim();
}

module.exports = { callLocalOllama };