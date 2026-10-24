import Anthropic from "@anthropic-ai/sdk";
import config from "../../public/app-config.json";

const anthropic = new Anthropic({
  apiKey: config.llm.apiToken,
  dangerouslyAllowBrowser: true,
});

type Turn = { role: "user" | "assistant"; text: string };

export async function summariseConversation(turns: Turn[]): Promise<string> {
  const msg = await anthropic.messages.create({
    model: config.llm.model,
    max_tokens: 200,
    system: "Summarise this conversation in two sentences for the conversation list.",
    messages: [{ role: "user", content: turns.map((t) => `${t.role}: ${t.text}`).join("\n") }],
  });
  const first = msg.content[0];
  return first.type === "text" ? first.text : "";
}
