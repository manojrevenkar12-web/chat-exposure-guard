import { marked } from "marked";
import ReactMarkdown from "react-markdown";

type Message = { role: "user" | "assistant"; content: string };

export function MessageBubble({ message }: { message: Message }) {
  if (message.role === "assistant") {
    return <div className="bubble assistant" dangerouslySetInnerHTML={{ __html: marked.parse(message.content) as string }} />;
  }
  return <div className="bubble user">{message.content}</div>;
}

export function CharacterGreeting({ greeting }: { greeting: { text: string } }) {
  return <ReactMarkdown>{greeting.text}</ReactMarkdown>;
}
