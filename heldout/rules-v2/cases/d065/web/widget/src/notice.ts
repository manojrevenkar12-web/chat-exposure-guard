export function showReplyNotice(container: HTMLElement, replyText: string): void {
  const p = document.createElement("p");
  p.className = "notice";
  p.textContent = replyText;
  container.replaceChildren(p);
}
