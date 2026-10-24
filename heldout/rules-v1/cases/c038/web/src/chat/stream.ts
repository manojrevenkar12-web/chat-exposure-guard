export async function streamReply(
  conversationId: string,
  text: string,
  bubble: HTMLElement,
): Promise<void> {
  const res = await fetch(`/api/conversations/${conversationId}/stream`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include",
    body: JSON.stringify({ text }),
  });
  if (!res.ok || !res.body) {
    throw new Error(`stream failed: ${res.status}`);
  }

  const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  let html = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value;
    const events = buffer.split("\n\n");
    buffer = events.pop() ?? "";
    for (const evt of events) {
      if (!evt.startsWith("data: ")) continue;
      const payload = JSON.parse(evt.slice(6)) as { delta?: string };
      if (payload.delta) {
        html += payload.delta.replace(/\n/g, "<br>");
        bubble.innerHTML = html;
      }
    }
  }
}
