import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

export function SafeMarkdown({ text }: { text: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      disallowedElements={["img"]}
      unwrapDisallowed
    >
      {text}
    </ReactMarkdown>
  );
}
