from datetime import datetime, timedelta, timezone

import psycopg
from psycopg import sql

PURGEABLE = {"messages": "created_at", "memories": "updated_at", "uploads": "created_at"}


def purge_older_than(conn: psycopg.Connection, table: str, user_id: int, days: int) -> int:
    if table not in PURGEABLE:
        raise ValueError(f"table {table!r} cannot be purged")
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    query = sql.SQL("DELETE FROM {table} WHERE user_id = %s AND {column} < %s").format(
        table=sql.Identifier(table),
        column=sql.Identifier(PURGEABLE[table]),
    )
    with conn.cursor() as cur:
        cur.execute(query, (user_id, cutoff))
        return cur.rowcount
