import express from "express";
import axios from "axios";

const router = express.Router();

router.post("/beth", async (req, res) => {
  try {
    const { prompt, contexto } = req.body;

    const response = await axios.post("http://localhost:11434/api/generate", {
      model: "llama3.1", // ou o nome exato do modelo que você baixou via `ollama pull`
      prompt: `
Você é a assistente Beth, especialista em Compras e Supply Chain.
Use o contexto a seguir para responder de forma estratégica e prática:

Contexto:
${contexto}

Pergunta:
${prompt}
      `,
      stream: false,
    });

    return res.json({ resposta: response.data.response });
  } catch (error) {
    console.error("Erro ao chamar Llama:", error.message);
    return res.status(500).json({ erro: "Falha ao gerar resposta da IA." });
  }
});

export default router;
