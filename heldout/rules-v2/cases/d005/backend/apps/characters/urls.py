from django.urls import path

from .views import CharacterDetailView

urlpatterns = [
    path("api/characters/<int:pk>/", CharacterDetailView.as_view(), name="character-detail"),
]
