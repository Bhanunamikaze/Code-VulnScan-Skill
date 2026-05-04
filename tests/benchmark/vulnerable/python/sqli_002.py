# BENCHMARK: vulnerable - sqli
from django.db import connection
from django.http import HttpResponse


def search_view(request):
    name = request.GET.get("name", "")
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM products WHERE name='" + name + "'")
        rows = cursor.fetchall()
    return HttpResponse(str(rows))
