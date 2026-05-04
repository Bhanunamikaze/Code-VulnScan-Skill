# BENCHMARK: safe - django_orm_parameterized
from django.http import JsonResponse
from myapp.models import User


def search_users(request):
    name = request.GET.get("name", "")
    # Safe: ORM uses parameterized queries internally
    users = User.objects.filter(name=name)
    return JsonResponse({"users": list(users.values())})
