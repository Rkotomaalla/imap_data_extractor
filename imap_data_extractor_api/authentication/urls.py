from django.urls import path
from .views import(
    login_view,
    logout_view,
    current_user_view,
    refresh_token_view
)

urlpatterns = [
    path('login/', login_view, name='login'),
     # Refresh le token
    path('refresh/', refresh_token_view, name='refresh_token_view'),
    
    # Logout
    path('logout/', logout_view, name='logout'),
    
    # Informations utilisateur
    path('me/', current_user_view, name='current_user'),
]