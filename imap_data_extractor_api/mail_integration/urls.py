from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import(
    MailIntegratioinView,
)

router = DefaultRouter()
router.register(r'', MailIntegratioinView, basename='mail_integration')
urlpatterns = [
    path('', include(router.urls)),
]