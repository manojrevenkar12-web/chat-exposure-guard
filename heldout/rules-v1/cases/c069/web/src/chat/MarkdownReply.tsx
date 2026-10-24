import ReactMarkdown from "react-markdown";
import type { Components } from "react-markdown";

const IMAGE_HOSTS = new Set(["media.lumachat.example.com", "cdn.lumachat.example.com"]);

function isAllowedImage(src?: string): boolean {
  if (!src) return false;
  try {
    const u = new URL(src, window.location.origin);
    return u.protocol === "https:" && IMAGE_HOSTS.has(u.hostname);
  } catch {
    return false;
  }
}

const components: Components = {
  img: ({ src, alt }) =>
    isAllowedImage(src) ? (
      <img src={src} alt={alt ?? ""} loading="lazy" referrerPolicy="no-referrer" />
    ) : (
      <span className="img-blocked">[image removed]</span>
    ),
};

export function MarkdownReply({ text }: { text: string }) {
  return <ReactMarkdown components={components}>{text}</ReactMarkdown>;
}
