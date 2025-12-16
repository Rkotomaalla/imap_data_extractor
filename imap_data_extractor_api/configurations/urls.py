from django.urls import path , include
from rest_framework.routers import DefaultRouter
from .views import(
    MongoConfigViewSet
)
router = DefaultRouter()
router.register(r'db', MongoConfigViewSet, basename='MongoConfig')
urlpatterns = [
    path('', include(router.urls)),
]