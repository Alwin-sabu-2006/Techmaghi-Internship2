/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from "express";
import path from "path";
import { createServer as createViteServer } from "vite";
import { GoogleGenAI, Type } from "@google/genai";
import dotenv from "dotenv";

dotenv.config();

let aiClient: GoogleGenAI | null = null;

function getGeminiClient() {
  if (!aiClient) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error("GEMINI_API_KEY environment variable is required");
    }
    aiClient = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build',
        },
      },
    });
  }
  return aiClient;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  app.use(express.json());

  // Simple API Route for sentiment analysis
  app.post("/api/analyze", async (req, res) => {
    try {
      const { text } = req.body;
      if (!text || typeof text !== "string" || text.trim() === "") {
        return res.status(400).json({ error: "Please enter some text." });
      }

      if (!process.env.GEMINI_API_KEY) {
        return res.status(400).json({
          error: "Gemini API key is missing. Add it in the 'Secrets' panel in Google AI Studio."
        });
      }

      const ai = getGeminiClient();

      const response = await ai.models.generateContent({
        model: "gemini-3.5-flash",
        contents: `Analyze the sentiment and emotional expression of this sentence:\n\n"${text}"`,
        config: {
          systemInstruction: "You are a helpful sentiment analyzer. Tell the overall sentiment, the expression/emotion detected, and explain why. Keep it clear, simple, and direct.",
          responseMimeType: "application/json",
          responseSchema: {
            type: Type.OBJECT,
            properties: {
              sentiment: {
                type: Type.STRING,
                description: "Must be exactly 'positive', 'negative', or 'neutral'."
              },
              emoji: {
                type: Type.STRING,
                description: "Single emoji that best represents the tone."
              },
              expression: {
                type: Type.STRING,
                description: "The primary expression or feeling (e.g., 'Happy', 'Angry', 'Peaceful')."
              },
              explanation: {
                type: Type.STRING,
                description: "A short, simple explanation of why this sentiment and expression were detected."
              }
            },
            required: ["sentiment", "emoji", "expression", "explanation"]
          }
        }
      });

      if (!response.text) {
        throw new Error("Failed to analyze the text.");
      }

      const result = JSON.parse(response.text.trim());
      res.json(result);
    } catch (error: any) {
      console.error("Analysis Error:", error);
      res.status(500).json({ error: error.message || "Something went wrong." });
    }
  });

  // Serve static assets through Vite in dev, node files in prod
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server launched on port ${PORT}`);
  });
}

startServer();
