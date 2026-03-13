from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import(
    MailIntegrationView,
)

router = DefaultRouter()
router.register(r'', MailIntegrationView, basename='mail_integration')
urlpatterns = [
    path('', include(router.urls)),
]