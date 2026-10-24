import Markdown, { type Components } from "react-markdown";

const components: Components = {
  img: ({ src, alt }) => (
    <img className="reply-image" src={src} alt={alt ?? ""} loading="lazy" referrerPolicy="no-referrer" />
  ),
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noopener noreferrer">
      {children}
    </a>
  ),
};

export default function RichReply({ markdown }: { markdown: string }) {
  return <Markdown components={components}>{markdown}</Markdown>;
}
