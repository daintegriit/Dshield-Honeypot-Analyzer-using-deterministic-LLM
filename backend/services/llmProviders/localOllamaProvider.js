// backend/services/llmProviders/localOllamaProvider.js

const OLLAMA_URL =
  process.env.OLLAMA_URL || "http://127.0.0.1:11434";

const DEFAULT_MODEL =
  process.env.OLLAMA_MODEL || "llama3.1:8b";

// ------------------------------------------------------------
// RUNTIME CONFIG
// ------------------------------------------------------------

const CONFIG = {

  REQUEST_TIMEOUT_MS: Number(
    process.env.OLLAMA_TIMEOUT_MS || 180000
  ),

  NUM_CTX: Number(
    process.env.OLLAMA_NUM_CTX || 8192
  ),

  NUM_PREDICT: Number(
    process.env.OLLAMA_NUM_PREDICT || 384
  ),

  NUM_THREAD: Number(
    process.env.OLLAMA_NUM_THREAD || 4
  ),

  TEMPERATURE: Number(
    process.env.OLLAMA_TEMPERATURE || 0.2
  ),

  TOP_P: Number(
    process.env.OLLAMA_TOP_P || 0.9
  ),

  REPEAT_PENALTY: Number(
    process.env.OLLAMA_REPEAT_PENALTY || 1.1
  ),

  KEEP_ALIVE:
    process.env.OLLAMA_KEEP_ALIVE || "15m",
};

// ------------------------------------------------------------
// LOGGING
// ------------------------------------------------------------

function log(msg, extra = null) {

  if (extra) {

    console.log(`[OLLAMA] ${msg}`, extra);

    return;
  }

  console.log(`[OLLAMA] ${msg}`);
}

// ------------------------------------------------------------
// SANITIZE
// ------------------------------------------------------------

function sanitizeResponse(text) {

  if (!text || typeof text !== "string") {

    return "";
  }

  return text
    .replace(/```json/gi, "")
    .replace(/```/g, "")
    .trim();
}

// ------------------------------------------------------------
// MAIN CALL
// ------------------------------------------------------------

async function callLocalOllama({

  prompt,

  model = null,

  temperature = CONFIG.TEMPERATURE,

}) {

  // ----------------------------------------------------------
  // NODE CHECK
  // ----------------------------------------------------------

  if (typeof fetch !== "function") {

    throw new Error(
      "Global fetch is not available. Node 18+ required."
    );
  }

  // ----------------------------------------------------------
  // PROMPT VALIDATION
  // ----------------------------------------------------------

  if (!prompt || typeof prompt !== "string") {

    throw new Error(
      "Prompt must be a non-empty string"
    );
  }

  // ----------------------------------------------------------
  // SAFE MODEL FALLBACK
  // ----------------------------------------------------------

  if (
    !model ||
    typeof model !== "string" ||
    !model.trim()
  ) {

    model = DEFAULT_MODEL;
  }

  const controller =
    new AbortController();

  const timeout =
    setTimeout(() => {

      controller.abort();

    }, CONFIG.REQUEST_TIMEOUT_MS);

  const started =
    Date.now();

  try {

    log("Starting Ollama inference", {

      model,

      num_ctx:
        CONFIG.NUM_CTX,

      num_predict:
        CONFIG.NUM_PREDICT,
    });

    const payload = {

      model,

      prompt,

      stream: false,

      keep_alive:
        CONFIG.KEEP_ALIVE,

      options: {

        temperature,

        top_p:
          CONFIG.TOP_P,

        repeat_penalty:
          CONFIG.REPEAT_PENALTY,

        num_ctx:
          CONFIG.NUM_CTX,

        num_predict:
          CONFIG.NUM_PREDICT,

        num_thread:
          CONFIG.NUM_THREAD,
      },
    };

    log("OLLAMA REQUEST", {

      url:
        `${OLLAMA_URL}/api/generate`,

      model,
    });

    const res =
      await fetch(

        `${OLLAMA_URL}/api/generate`,

        {

          method: "POST",

          headers: {

            "Content-Type":
              "application/json",
          },

          signal:
            controller.signal,

          body:
            JSON.stringify(payload),
        }
      );

    const elapsed =
      Date.now() - started;

    // ----------------------------------------------------------
    // NON-200 HANDLING
    // ----------------------------------------------------------

    if (!res.ok) {

      const text =
        await res.text();

      log("OLLAMA NON-200 RESPONSE", {

        status:
          res.status,

        body:
          text,

        model,
      });

      throw new Error(

        `Ollama error ${res.status}: ${text}`
      );
    }

    // ----------------------------------------------------------
    // RAW RESPONSE
    // ----------------------------------------------------------

    const rawText =
      await res.text();

    console.log(
      "\n================ RAW OLLAMA RESPONSE ================\n"
    );

    console.log(rawText);

    console.log(
      "\n=====================================================\n"
    );

    let data;

    try {

      data =
        JSON.parse(rawText);

    } catch (err) {

      throw new Error(

        `Failed to parse Ollama response: ${err.message}`
      );
    }

    // ----------------------------------------------------------
    // VALIDATE RESPONSE
    // ----------------------------------------------------------

    if (
      !data ||
      typeof data.response !== "string"
    ) {

      log("MALFORMED OLLAMA RESPONSE", {

        model,

        keys:
          data
            ? Object.keys(data)
            : null,

        raw:
          data,
      });

      throw new Error(
        "Malformed Ollama response"
      );
    }

    const cleaned =
      sanitizeResponse(
        data.response
      );

    // ----------------------------------------------------------
    // FINAL METRICS
    // ----------------------------------------------------------

    log("Inference completed", {

      model,

      elapsed_ms:
        elapsed,

      prompt_tokens:
        data.prompt_eval_count || 0,

      completion_tokens:
        data.eval_count || 0,

      total_tokens:
        (
          (data.prompt_eval_count || 0)
          +
          (data.eval_count || 0)
        ),
    });

    return {

      model,

      response:
        cleaned,

      tokenMetrics: {

        promptTokens:
          data.prompt_eval_count || 0,

        completionTokens:
          data.eval_count || 0,

        totalTokens:
          (
            (data.prompt_eval_count || 0)
            +
            (data.eval_count || 0)
          ),

        promptEvalDuration:
          data.prompt_eval_duration || 0,

        evalDuration:
          data.eval_duration || 0,
      },

      raw: data,
    };

  } catch (err) {

    if (
      err.name === "AbortError"
    ) {

      throw new Error(

        `Ollama request timed out after ${CONFIG.REQUEST_TIMEOUT_MS}ms`
      );
    }

    throw err;

  } finally {

    clearTimeout(timeout);
  }
}

// ------------------------------------------------------------
// EXPORTS
// ------------------------------------------------------------

module.exports = {

  callLocalOllama,
};