import json
import os
import subprocess

import psycopg

EXPORT_ROOT = "/var/lib/kindred/exports"


def export_user_data(dsn: str, user_id: str) -> str:
    export_dir = os.path.join(EXPORT_ROOT, user_id)
    os.makedirs(export_dir, exist_ok=True)

    with psycopg.connect(dsn) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT id, title, created_at FROM conversations WHERE user_id = '%s'" % user_id
        )
        conversations = [
            {"id": r[0], "title": r[1], "created_at": r[2].isoformat()} for r in cur.fetchall()
        ]

    with open(os.path.join(export_dir, "conversations.json"), "w") as fh:
        json.dump(conversations, fh)

    archive = f"{EXPORT_ROOT}/{user_id}.tar.gz"
    subprocess.run(f"tar -czf {archive} -C {export_dir} .", shell=True, check=True)
    return archive
