import Anthropic from "@anthropic-ai/sdk";
import { FormEvent, useState } from "react";

const client = new Anthropic({
  apiKey: import.meta.env.VITE_ANTHROPIC_API_KEY,
  dangerouslyAllowBrowser: true,
});

const PERSONA = "You are Juniper, a friendly companion. Keep replies short.";

export function QuickChat() {
  const [input, setInput] = useState("");
  const [reply, setReply] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      const resp = await client.messages.create({
        model: "claude-haiku-4-5",
        max_tokens: 400,
        system: PERSONA,
        messages: [{ role: "user", content: input }],
      });
      const first = resp.content[0];
      setReply(first.type === "text" ? first.text : "");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="quick-chat">
      <textarea value={input} onChange={(e) => setInput(e.target.value)} />
      <button disabled={busy}>Send</button>
      <div className="reply" dangerouslySetInnerHTML={{ __html: reply }} />
    </form>
  );
}
