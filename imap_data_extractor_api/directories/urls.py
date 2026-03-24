from django.urls import path , include
from rest_framework.routers import DefaultRouter
from .views import(
    DirectoryViewSet
)
router = DefaultRouter()
router.register(r'', DirectoryViewSet, basename='directory')
urlpatterns = [
    path('', include(router.urls)),
]