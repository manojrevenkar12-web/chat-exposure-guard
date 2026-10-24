import ReactMarkdown from "react-markdown";

export function Reply({ message }: { message: { content: string } }) {
  // ruleid: ceg.markdown-images-unrestricted
  return <ReactMarkdown>{message.content}</ReactMarkdown>;
}

export function GuardedReply({ message }: { message: { content: string } }) {
  // ok: ceg.markdown-images-unrestricted
  return <ReactMarkdown components={{ img: SafeImage }}>{message.content}</ReactMarkdown>;
}

export function TextOnly({ reply }: { reply: string }) {
  // ok: ceg.markdown-images-unrestricted
  return <ReactMarkdown disallowedElements={["img"]}>{reply}</ReactMarkdown>;
}


const components: Components = {
  img: ({ src }) => (allowed(src) ? <img src={src} /> : <span>[image removed]</span>),
};

export function Restricted({ text }: { text: string }) {
  // ok: ceg.markdown-images-unrestricted
  return <ReactMarkdown components={components}>{text}</ReactMarkdown>;
}

const md = new MarkdownIt({ html: false, linkify: true });

export function ViaMarkdownIt({ reply }: { reply: string }) {
  // ruleid: ceg.markdown-images-unrestricted
  const html = DOMPurify.sanitize(md.render(reply));
  return <article dangerouslySetInnerHTML={{ __html: html }} />;
}


export function MultiLine({ markdown }: { markdown: string }) {
  // ruleid: ceg.markdown-images-unrestricted
  return <Markdown remarkPlugins={[remarkGfm]}>
      {markdown}
    </Markdown>;
}


const codeOnly = {
  code: ({ children }) => <code>{children}</code>,
};

export function VariableWithoutImg({ reply }: { reply: string }) {
  // ruleid: ceg.markdown-images-unrestricted
  return <ReactMarkdown components={codeOnly}>{reply}</ReactMarkdown>;
}

export function InlineWithoutImg({ reply }: { reply: string }) {
  // ruleid: ceg.markdown-images-unrestricted
  return <ReactMarkdown components={{ a: Link }}>{reply}</ReactMarkdown>;
}
