import DOMPurify from "dompurify";
import MarkdownIt from "markdown-it";

const md = new MarkdownIt({ html: false, linkify: true });
md.disable("image");

export function renderAssistant(el: HTMLElement, text: string): void {
  el.innerHTML = DOMPurify.sanitize(md.render(text), { FORBID_TAGS: ["img"] });
}
