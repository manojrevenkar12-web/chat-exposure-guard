from http import HTTPStatus

from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required

from ..extensions import db
from ..models import Memory

edit_bp = Blueprint("memory_edit", __name__)

MAX_LEN = 500


def _load_for_edit(memory_id: int) -> Memory:
    memory = db.session.get(Memory, memory_id)
    if memory is None or memory.owner_id != current_user.id:
        abort(HTTPStatus.NOT_FOUND)
    return memory


@edit_bp.patch("/api/memories/<int:memory_id>")
@login_required
def patch_memory(memory_id: int):
    memory = _load_for_edit(memory_id)
    body = request.get_json(force=True) or {}
    text = (body.get("text") or "").strip()
    if not text or len(text) > MAX_LEN:
        abort(HTTPStatus.BAD_REQUEST)
    memory.text = text
    memory.pinned = bool(body.get("pinned", memory.pinned))
    db.session.commit()
    return jsonify(memory.to_dict())
