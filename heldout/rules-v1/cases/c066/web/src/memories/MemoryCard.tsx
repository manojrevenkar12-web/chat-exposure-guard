import { renderMemory } from "./format";

type Memory = { id: string; text: string; createdAt: string };

type Props = {
  memory: Memory;
  onDelete: (id: string) => void;
};

export function MemoryCard({ memory, onDelete }: Props) {
  return (
    <li className="memory-card">
      <p className="memory-card__text" dangerouslySetInnerHTML={{ __html: renderMemory(memory.text) }} />
      <time dateTime={memory.createdAt}>{new Date(memory.createdAt).toLocaleDateString()}</time>
      <button onClick={() => onDelete(memory.id)} aria-label="Forget this">
        Forget
      </button>
    </li>
  );
}
