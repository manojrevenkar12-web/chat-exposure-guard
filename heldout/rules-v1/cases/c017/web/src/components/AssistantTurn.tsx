import { MessageBody } from "./MessageBody";

type Props = { reply: { id: string; text: string; model: string } };

export function AssistantTurn({ reply }: Props) {
  return (
    <section className="turn turn--assistant" data-message-id={reply.id}>
      <MessageBody content={reply.text} />
      <footer className="turn__meta">{reply.model}</footer>
    </section>
  );
}
