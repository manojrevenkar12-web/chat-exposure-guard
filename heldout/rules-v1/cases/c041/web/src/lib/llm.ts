import OpenAI from "openai";

const openai = new OpenAI({
  apiKey: import.meta.env.VITE_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export async function suggestReplies(lastMessage: string): Promise<string[]> {
  const res = await openai.chat.completions.create({
    model: "gpt-4.1-mini",
    messages: [
      { role: "system", content: "Suggest three short, friendly replies. Return one per line." },
      { role: "user", content: lastMessage },
    ],
  });
  return (res.choices[0].message.content ?? "")
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean)
    .slice(0, 3);
}
