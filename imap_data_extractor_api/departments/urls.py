from django.urls import path
from .views import(
    get_all_department
)

urlpatterns = [
    path('', get_all_department, name='departments'),
]