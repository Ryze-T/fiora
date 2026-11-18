from django.utils.safestring import mark_safe
from django.http import HttpResponse
def comment_view(request):
    body = request.GET.get("body")
    return HttpResponse(mark_safe("<div>" + body + "</div>"))
