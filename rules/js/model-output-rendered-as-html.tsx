import DOMPurify from "dompurify";
import { marked } from "marked";

export function Bubble({ message }: { message: { content: string } }) {
  // ruleid: ceg.model-output-rendered-as-html
  return <div className="bubble" dangerouslySetInnerHTML={{ __html: marked.parse(message.content) }} />;
}

export function SafeBubble({ message }: { message: { content: string } }) {
  // ok: ceg.model-output-rendered-as-html
  return <div className="bubble" dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(marked.parse(message.content)) }} />;
}

export function stream(el: HTMLElement, delta: string) {
  // ruleid: ceg.model-output-rendered-as-html
  el.innerHTML += delta;
}

export function plain(el: HTMLElement, reply: string) {
  // ok: ceg.model-output-rendered-as-html
  el.textContent = reply;
}

export function Static() {
  // ok: ceg.model-output-rendered-as-html
  return <div dangerouslySetInnerHTML={{ __html: LEGAL_FOOTER }} />;
}


export function stream(bubble: HTMLElement, deltas: string[]) {
  let html = "";
  for (const d of deltas) {
    html += d;
    // ruleid: ceg.model-output-rendered-as-html
    bubble.innerHTML = html;
  }
}

export function Clean({ reply }: { reply: string }) {
  const html = DOMPurify.sanitize(render(reply));
  // ok: ceg.model-output-rendered-as-html
  return <article dangerouslySetInnerHTML={{ __html: html }} />;
}
