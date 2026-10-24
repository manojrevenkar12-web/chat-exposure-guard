import logging
import time

logger = logging.getLogger("chat.telemetry")


def log_turn(conversation_id, user_message, reply, usage, started: float) -> None:
    logger.info(
        "turn conversation=%s user_msg_id=%s reply_id=%s user_chars=%d reply_chars=%d "
        "in_tokens=%d out_tokens=%d latency_ms=%d",
        conversation_id,
        user_message.id,
        reply.id,
        len(user_message.body),
        len(reply.body),
        usage.input_tokens,
        usage.output_tokens,
        int((time.monotonic() - started) * 1000),
    )


def log_refusal(conversation_id, reply) -> None:
    logger.warning(
        "model refused conversation=%s reply_id=%s stop_reason=%s",
        conversation_id,
        reply.id,
        reply.stop_reason,
    )
