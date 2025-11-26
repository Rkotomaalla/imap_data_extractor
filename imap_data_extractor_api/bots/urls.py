from django.urls import path
from .views import(
    BotsView
)

urlpatterns = [
    path('', BotsView.as_view(), name='bots_view'),
]