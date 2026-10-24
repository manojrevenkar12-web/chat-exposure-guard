import DOMPurify from "dompurify";
import { Marked } from "marked";

const IMAGE_HOSTS = new Set(["media.kindred.chat"]);

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

const marked = new Marked({
  renderer: {
    image({ href, text }) {
      try {
        const url = new URL(href);
        if (url.protocol === "https:" && IMAGE_HOSTS.has(url.hostname)) {
          return `<img src="${escapeHtml(url.toString())}" alt="${escapeHtml(text)}">`;
        }
      } catch {
        // fall through: not an absolute URL
      }
      return `<span class="img-alt">${escapeHtml(text)}</span>`;
    },
  },
});

export function renderChatMarkdown(text: string): string {
  return DOMPurify.sanitize(marked.parse(text, { async: false }) as string);
}
