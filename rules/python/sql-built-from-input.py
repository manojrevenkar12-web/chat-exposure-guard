from sqlalchemy import text


def search(cur, db, user_id, term):
    # ruleid: ceg.sql-built-from-input
    cur.execute(f"SELECT * FROM messages WHERE user_id = {user_id} AND text LIKE '%{term}%'")
    # ruleid: ceg.sql-built-from-input
    cur.execute("SELECT * FROM messages WHERE user_id = %s" % user_id)
    # ruleid: ceg.sql-built-from-input
    db.execute(text(f"DELETE FROM memories WHERE id = {term}"))
    q = f"SELECT * FROM conversations WHERE title = '{term}'"
    # ruleid: ceg.sql-built-from-input
    cur.execute(q)
    # ok: ceg.sql-built-from-input
    cur.execute("SELECT * FROM messages WHERE user_id = %s", (user_id,))
    # ok: ceg.sql-built-from-input
    db.execute(text("SELECT * FROM messages WHERE id = :id"), {"id": term})
