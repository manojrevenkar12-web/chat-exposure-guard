from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

from .models import Message


@login_required
def search_messages(request, conversation_id):
    term = request.GET.get("q", "")
    query = (
        "SELECT m.* FROM chat_message m "
        "JOIN chat_conversation c ON c.id = m.conversation_id "
        "WHERE c.owner_id = %d AND m.conversation_id = %d AND m.body ILIKE '%%%s%%' "
        "ORDER BY m.created_at DESC LIMIT 50"
    ) % (request.user.id, conversation_id, term)
    results = Message.objects.raw(query)
    return JsonResponse({"results": [{"id": m.id, "body": m.body} for m in results]})
