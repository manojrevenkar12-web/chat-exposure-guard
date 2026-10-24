import logging
import os
from datetime import datetime, timedelta, timezone

import psycopg2

log = logging.getLogger("retention")

RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "30"))


def purge_deleted_conversations(conn, batch_size: int = 5000) -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    total = 0
    with conn.cursor() as cur:
        while True:
            cur.execute(
                """
                DELETE FROM messages
                WHERE id IN (
                    SELECT m.id FROM messages m
                    JOIN conversations c ON c.id = m.conversation_id
                    WHERE c.deleted_at IS NOT NULL AND c.deleted_at < %s
                    LIMIT %s
                )
                """,
                (cutoff, batch_size),
            )
            deleted = cur.rowcount
            conn.commit()
            total += deleted
            log.info("purged batch of %d messages (cutoff=%s)", deleted, cutoff.isoformat())
            if deleted < batch_size:
                return total


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    with psycopg2.connect(os.environ["DATABASE_URL"]) as connection:
        removed = purge_deleted_conversations(connection)
        log.info("retention run finished, %d messages removed", removed)
