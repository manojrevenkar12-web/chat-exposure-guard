import argparse
import csv
import os

import psycopg2


def export(conn, email: str, out_path: str) -> int:
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE email = '%s'" % email)
    row = cur.fetchone()
    if row is None:
        raise SystemExit(f"no user with that email")
    user_id = row[0]

    cur.execute(
        """
        SELECT c.id, c.title, m.role, m.created_at, m.body
        FROM conversations c
        JOIN messages m ON m.conversation_id = c.id
        WHERE c.user_id = %s
        ORDER BY c.id, m.created_at
        """,
        (user_id,),
    )
    n = 0
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["conversation_id", "title", "role", "created_at", "text"])
        for rec in cur:
            writer.writerow(rec)
            n += 1
    return n


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GDPR data export for one account")
    parser.add_argument("email")
    parser.add_argument("--out", default="export.csv")
    args = parser.parse_args()
    with psycopg2.connect(os.environ["DATABASE_URL"]) as conn:
        count = export(conn, args.email, args.out)
    print(f"wrote {count} rows to {args.out}")
