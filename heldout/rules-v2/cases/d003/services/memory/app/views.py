from flask import Blueprint, abort, current_app, jsonify
from flask_login import current_user, login_required

from .extensions import db
from .models import Memory

bp = Blueprint("memories", __name__, url_prefix="/api/memories")


@bp.route("/<int:memory_id>", methods=["GET"])
@login_required
def get_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    if memory.user_id != current_user.id:
        abort(404)
    return jsonify(memory.to_dict())


@bp.route("/<int:memory_id>", methods=["DELETE"])
@login_required
def delete_memory(memory_id):
    memory = Memory.query.get_or_404(memory_id)
    db.session.delete(memory)
    db.session.commit()
    current_app.logger.info("user %s deleted memory %s", current_user.id, memory_id)
    return jsonify({"deleted": memory_id}), 200
