from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import(
    OutlookIntegrationView,
)

router = DefaultRouter()
router.register(r'', OutlookIntegrationView, basename='outlook_integration')
urlpatterns = [
    path('', include(router.urls)),
]