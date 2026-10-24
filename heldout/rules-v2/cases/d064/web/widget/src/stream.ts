type Chunk = { conversationId: string; delta: string; done: boolean };

export function attachStream(source: EventSource, bubble: HTMLElement): void {
  source.addEventListener("chunk", (event) => {
    const chunk: Chunk = JSON.parse((event as MessageEvent).data);
    bubble.innerHTML += chunk.delta;
    if (chunk.done) {
      bubble.classList.remove("pending");
      source.close();
    }
  });
}

export function renderHistory(list: HTMLUListElement, replies: { id: string; text: string }[]): void {
  for (const reply of replies) {
    list.insertAdjacentHTML(
      "beforeend",
      `<li class="msg bot" data-id="${reply.id}">${reply.text}</li>`,
    );
  }
}
