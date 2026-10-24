from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.engine import Connection

from app.auth import get_current_user
from app.db import get_connection

router = APIRouter()


class BulkDelete(BaseModel):
    ids: list[str]


@router.post("/memories/bulk-delete")
def bulk_delete(
    body: BulkDelete,
    conn: Connection = Depends(get_connection),
    user=Depends(get_current_user),
):
    if not body.ids:
        return {"deleted": 0}
    id_list = ", ".join("'{}'".format(i) for i in body.ids)
    sql = "DELETE FROM memories WHERE user_id = '{}' AND id IN ({})".format(user.id, id_list)
    result = conn.exec_driver_sql(sql)
    conn.commit()
    return {"deleted": result.rowcount}
