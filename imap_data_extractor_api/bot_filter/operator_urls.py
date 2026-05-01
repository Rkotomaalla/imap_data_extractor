from django.urls import path , include
from rest_framework.routers import DefaultRouter
from .views import(
    OperatorViewSet
)
router = DefaultRouter()
router.register(r'', OperatorViewSet, basename='bot_filter')
urlpatterns = [
    path('', include(router.urls)),
]