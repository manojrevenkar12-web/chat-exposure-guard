from django.contrib.auth.decorators import login_required
from django.http import JsonResponse

from .models import Message


@login_required
def lookup(request, conversation_id):
    term = request.GET.get("q", "")
    rows = (
        Message.objects.filter(
            conversation__owner=request.user,
            conversation_id=conversation_id,
            body__icontains=term,
        )
        .order_by("-created_at")[:50]
    )
    return JsonResponse({"results": [{"id": m.id, "body": m.body} for m in rows]})
