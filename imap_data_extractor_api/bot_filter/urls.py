from django.urls import path , include
from rest_framework.routers import DefaultRouter
from .views import(
    FieldViewSet
)
router = DefaultRouter()
router.register(r'', FieldViewSet, basename='bot_filter')
urlpatterns = [
    path('', include(router.urls)),
]