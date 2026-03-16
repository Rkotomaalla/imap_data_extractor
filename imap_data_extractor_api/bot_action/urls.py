from django.urls import path , include
from rest_framework.routers import DefaultRouter
from .views import(
    ActionViewSet
)
router = DefaultRouter()
router.register(r'', ActionViewSet, basename='action')
urlpatterns = [
    path('', include(router.urls)),
]