from django.contrib.auth.decorators import login_required
from django.http import FileResponse, JsonResponse
from django.shortcuts import get_object_or_404
from django.views.decorators.http import require_http_methods

from .models import Upload


@login_required
@require_http_methods(["GET"])
def download_upload(request, upload_id):
    upload = get_object_or_404(Upload, pk=upload_id, owner=request.user)
    return FileResponse(upload.file.open("rb"), content_type=upload.content_type)


@login_required
@require_http_methods(["DELETE"])
def delete_upload(request, upload_id):
    upload = get_object_or_404(Upload.objects.filter(owner=request.user), pk=upload_id)
    upload.file.delete(save=False)
    upload.delete()
    return JsonResponse({"deleted": upload_id})
