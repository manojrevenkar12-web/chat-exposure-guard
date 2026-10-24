import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export function MarkdownReply({ text }: { text: string }) {
  return (
    <div className="md-reply">
      <ReactMarkdown remarkPlugins={[remarkGfm]}>{text}</ReactMarkdown>
    </div>
  );
}
