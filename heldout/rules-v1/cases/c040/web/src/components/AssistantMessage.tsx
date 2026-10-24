import DOMPurify from "dompurify";
import MarkdownIt from "markdown-it";

const md = new MarkdownIt({ html: false, linkify: true, breaks: true });

export function AssistantMessage({ reply }: { reply: string }) {
  const html = DOMPurify.sanitize(md.render(reply));
  return <article className="msg msg--assistant" dangerouslySetInnerHTML={{ __html: html }} />;
}
