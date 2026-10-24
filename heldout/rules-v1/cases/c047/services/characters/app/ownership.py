from typing import TypeVar

from fastapi import HTTPException
from sqlalchemy.orm import Session

T = TypeVar("T")


def get_owned_or_404(db: Session, model: type[T], obj_id, user) -> T:
    obj = db.get(model, obj_id)
    if obj is None or obj.owner_id != user.id:
        raise HTTPException(status_code=404, detail="not found")
    return obj
