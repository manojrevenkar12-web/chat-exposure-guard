import DOMPurify from "dompurify";
import MarkdownIt from "markdown-it";

const md = new MarkdownIt({ linkify: true, breaks: true });

export function renderReply(target: HTMLElement, replyMarkdown: string): void {
  const html = md.render(replyMarkdown);
  target.innerHTML = DOMPurify.sanitize(html, { USE_PROFILES: { html: true } });
}
