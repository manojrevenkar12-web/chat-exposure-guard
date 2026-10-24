import logging

logger = logging.getLogger(__name__)


def handle(message, user):
    # ruleid: ceg.chat-content-logged
    logger.info("user %s said %s", user.id, message.content)
    # ruleid: ceg.chat-content-logged
    logger.debug(f"completion: {completion.text}")
    # ruleid: ceg.chat-content-logged
    print("prompt was", request.prompt)
    # ok: ceg.chat-content-logged
    logger.info("user %s sent a message of %d chars", user.id, len(message.content))
    # ok: ceg.chat-content-logged
    logger.info("message %s stored", message.id)
    # ok: ceg.chat-content-logged
    logger.info("settings %s", settings.text)


def extract(facts, user_id, body, reply, text):
    for fact in facts:
        # ruleid: ceg.chat-content-logged
        logger.debug("new memory for %s: %r", user_id, fact)
    # ruleid: ceg.chat-content-logged
    logger.info("incoming %s", body.text)
    # ruleid: ceg.chat-content-logged
    print(f"[llm] -> {reply}")
    # ok: ceg.chat-content-logged
    logger.info("extracted %d memories", len(facts))
    # ok: ceg.chat-content-logged
    logger.info("reply sent to %s", user_id)


def telemetry(reply, user_message):
    # ok: ceg.chat-content-logged
    logger.info("reply=%s chars=%d stop=%s", reply.id, len(reply.body), reply.stop_reason)
