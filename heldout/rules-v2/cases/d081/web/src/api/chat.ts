export type ChatTurn = { role: "user" | "assistant"; content: string };

export async function sendMessage(conversationId: string, text: string): Promise<ChatTurn> {
  const res = await fetch(`/api/conversations/${encodeURIComponent(conversationId)}/messages`, {
    method: "POST",
    credentials: "include",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text }),
  });
  if (!res.ok) {
    throw new Error(`send failed: ${res.status}`);
  }
  return res.json();
}
