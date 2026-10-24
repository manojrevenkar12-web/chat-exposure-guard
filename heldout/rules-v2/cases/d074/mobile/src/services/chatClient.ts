import OpenAI from "openai";
import Config from "react-native-config";

const openai = new OpenAI({
  apiKey: Config.OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export async function sendToCompanion(history: { role: "user" | "assistant"; content: string }[]) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "system", content: "You are Nova, a cheerful companion." }, ...history],
  });
  return completion.choices[0]?.message?.content ?? "";
}
