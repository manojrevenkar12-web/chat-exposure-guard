import DOMPurify from "dompurify";
import { marked } from "marked";
import { useMemo } from "react";

const PURIFY_CONFIG = {
  ALLOWED_TAGS: [
    "p", "br", "strong", "em", "code", "pre", "blockquote",
    "ul", "ol", "li", "h3", "h4", "a", "table", "thead", "tbody", "tr", "th", "td",
  ],
  ALLOWED_ATTR: ["href", "title"],
  ALLOW_DATA_ATTR: false,
};

export function RichReply({ text }: { text: string }) {
  const html = useMemo(
    () => DOMPurify.sanitize(marked.parse(text, { async: false }) as string, PURIFY_CONFIG),
    [text],
  );
  return <div className="reply-rich" dangerouslySetInnerHTML={{ __html: html }} />;
}
