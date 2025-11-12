// api/services/bethService.js
// Beth usando Llama local: tenta Ollama primeiro (http://127.0.0.1:11434),
// e faz fallback para servidor llama.cpp (http://127.0.0.1:8080) se configurado.

require('dotenv').config();

// ====== Polyfill de fetch (Node 16/18) ======
const ensureFetch = async () => {
  if (typeof fetch !== 'function') {
    const { default: _fetch } = await import('node-fetch');
    global.fetch = _fetch;
  }
};
ensureFetch();

// ====== Config ======
const OLLAMA_URL   = process.env.OLLAMA_URL   || 'http://127.0.0.1:11434';
const OLLAMA_MODEL = process.env.OLLAMA_MODEL || 'llama3.1:latest';
const LLAMACPP_URL = process.env.LLAMACPP_URL || ''; // ex: 'http://127.0.0.1:8080'

// ====== Helpers ======
function buildPrompt({ pergunta, contexto, notas }) {
  const sys = `
Você é a Beth, analista de compras/financeiro. Responda em PT-BR, direta e acionável.
Se houver contexto/notas em JSON, use SOMENTE esses dados. Liste riscos e próximos passos quando fizer sentido.
Quando apropriado, ANEXE ao final um bloco JSON de análise entre os marcadores:
<<<ANALYSIS_JSON>>>
{ ... }
<<<END>>>
`.trim();

  const ctx = typeof contexto === 'string'
    ? contexto
    : (contexto ? JSON.stringify(contexto, null, 2) : '');

  const notasStr = notas != null ? JSON.stringify(notas, null, 2) : '';

  return `
${sys}

=== PERGUNTA ===
${String(pergunta || '').trim()}

${ctx ? `\n=== CONTEXTO ===\n\`\`\`json\n${ctx}\n\`\`\`\n` : '' }
${notasStr ? `\n=== NOTAS ===\n\`\`\`json\n${notasStr}\n\`\`\`\n` : '' }
`.trim();
}

function extractAnalysisJson(text) {
  try {
    const m1 = text.match(/<<<ANALYSIS_JSON>>>\s*([\s\S]*?)\s*<<<END>>>/i);
    if (m1?.[1]) return JSON.parse(m1[1]);
    const m2 = text.match(/```json\s*([\s\S]*?)\s*```/i);
    if (m2?.[1]) return JSON.parse(m2[1]);
  } catch {}
  return null;
}

function stripAnalysisBlocks(text) {
  return String(text || '')
    .replace(/<<<ANALYSIS_JSON>>>[\s\S]*?<<<END>>>/gi, '')
    .replace(/```json[\s\S]*?```/gi, '')
    .trim();
}

// ====== Ollama ======
async function callOllamaGenerate({ prompt }) {
  const url = `${OLLAMA_URL.replace(/\/+$/,'')}/api/generate`;
  const body = {
    model: OLLAMA_MODEL,
    prompt,
    stream: false,
    options: { temperature: 0.4, top_p: 0.9, top_k: 40, num_ctx: 8192 }
  };

  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => '');
    throw new Error(`Ollama HTTP ${r.status}: ${txt || r.statusText}`);
  }

  const json = await r.json();
  const text = json?.response ?? '';
  return String(text || '').trim();
}

// ====== llama.cpp (servidor nativo) ======
async function callLlamaCppCompletion({ prompt }) {
  if (!LLAMACPP_URL) throw new Error('LLAMACPP_URL não configurada.');
  const url = `${LLAMACPP_URL.replace(/\/+$/,'')}/completion`;
  const body = {
    prompt,
    n_predict: 1024,
    temperature: 0.4,
    top_p: 0.9,
    repeat_penalty: 1.1,
    stop: []
  };

  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });

  if (!r.ok) {
    const txt = await r.text().catch(() => '');
    throw new Error(`llama.cpp HTTP ${r.status}: ${txt || r.statusText}`);
  }

  const json = await r.json();
  const text = json?.content || json?.completion || '';
  return String(text || '').trim();
}

// ====== API síncrona ======
async function bethChat({ pergunta, contexto, notas } = {}) {
  if (!pergunta) throw new Error("Informe 'pergunta'.");

  const prompt = buildPrompt({ pergunta, contexto, notas });

  try {
    return await callOllamaGenerate({ prompt });
  } catch (e1) {
    try {
      if (LLAMACPP_URL) {
        return await callLlamaCppCompletion({ prompt });
      }
    } catch (e2) {
      throw new Error(
        `Falha ao consultar a IA (Llama).\n` +
        `- Ollama: ${e1?.message || e1}\n` +
        (LLAMACPP_URL ? `- llama.cpp: ${e2?.message || e2}\n` : '') +
        `Verifique se o servidor está ativo e o modelo está disponível.`
      );
    }
    throw new Error(
      `Falha ao consultar a IA (Llama via Ollama): ${e1?.message || e1}\n` +
      `Verifique se o Ollama está rodando e se o modelo '${OLLAMA_MODEL}' foi baixado.`
    );
  }
}

// ====== API streaming ======
async function callOllamaStream({ prompt, onToken }) {
  const url = `${OLLAMA_URL.replace(/\/+$/,'')}/api/generate`;
  const r = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: OLLAMA_MODEL,
      prompt,
      stream: true,
      options: { temperature: 0.4, top_p: 0.9, top_k: 40, num_ctx: 8192 }
    })
  });
  if (!r.ok) throw new Error(`Ollama HTTP ${r.status}`);

  // stream de linhas JSON ({response: "...", done: bool})
  const reader = r.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    const parts = buf.split('\n');
    for (let i = 0; i < parts.length - 1; i++) {
      const line = parts[i].trim();
      if (!line) continue;
      try {
        const json = JSON.parse(line);
        if (json.response) onToken?.(json.response);
      } catch {}
    }
    buf = parts[parts.length - 1]; // resta a parte incompleta
  }
}

async function bethStream({ pergunta, contexto, notas, onToken, onDone }) {
  const prompt = buildPrompt({ pergunta, contexto, notas });
  try {
    await callOllamaStream({ prompt, onToken });
    onDone?.();
  } catch (e1) {
    if (LLAMACPP_URL) {
      const full = await callLlamaCppCompletion({ prompt });
      onToken?.(full);
      onDone?.();
      return;
    }
    throw e1;
  }
}

module.exports = {
  bethChat,
  bethStream,
  extractAnalysisJson,
  stripAnalysisBlocks,
};
