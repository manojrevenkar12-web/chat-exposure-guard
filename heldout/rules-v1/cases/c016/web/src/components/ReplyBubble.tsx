import { memo } from "react";
import type { ChatMessage } from "../types";

type Props = {
  message: ChatMessage;
  onRetry?: () => void;
};

function ReplyBubble({ message, onRetry }: Props) {
  return (
    <div className={`bubble bubble--${message.role}`}>
      <div className="bubble__text" dangerouslySetInnerHTML={{ __html: message.text }} />
      {message.role === "assistant" && onRetry && (
        <button className="bubble__retry" onClick={onRetry}>
          Regenerate
        </button>
      )}
    </div>
  );
}

export default memo(ReplyBubble);
