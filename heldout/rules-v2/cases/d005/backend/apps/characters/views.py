import json

from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.http import HttpResponseBadRequest, JsonResponse
from django.views import View

from .models import Character


class CharacterDetailView(LoginRequiredMixin, View):
    editable_fields = ("name", "greeting", "description", "avatar_key")

    def get(self, request, pk):
        character = Character.objects.get(
            Q(pk=pk) & (Q(owner=request.user) | Q(is_published=True))
        )
        return JsonResponse(character.to_dict())

    def patch(self, request, pk):
        character = Character.objects.get(pk=pk)
        try:
            payload = json.loads(request.body)
        except ValueError:
            return HttpResponseBadRequest("invalid json")
        for field in self.editable_fields:
            if field in payload:
                setattr(character, field, payload[field])
        character.full_clean()
        character.save()
        return JsonResponse(character.to_dict())
