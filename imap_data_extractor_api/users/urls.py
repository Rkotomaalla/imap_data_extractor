from django.urls import path
from .views import(
    UserLdapView,
    UserLdapDetailView,
    UserMailView,
    UserSimpleAuth
)

urlpatterns = [
    path('auth_user', UserSimpleAuth.as_view(), name='user-simple-auth'),
    path('', UserLdapView.as_view(), name='user-ldap-create'),
    path('<int:user_id>',UserLdapDetailView.as_view(), name='user-ldap-detail'),
    path('<int:pk>/mail', UserMailView.as_view(), name='user-mail'),  # <-- nouveau endpoint
]