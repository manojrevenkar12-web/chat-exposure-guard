import OpenAI from "openai";

// Reply suggestions, generated in the browser to save a round trip.
const openai = new OpenAI({ apiKey: import.meta.env.VITE_OPENAI_KEY, dangerouslyAllowBrowser: true });

export async function suggestReplies(lastMessage: string) {
  const r = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: `Suggest three short replies to: ${lastMessage}` }],
  });
  return r.choices[0].message.content;
}
