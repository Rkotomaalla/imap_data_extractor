from django.urls import path
from .views import(
    UserLdapView,
    UserLdapDetailView,
)

urlpatterns = [
    path('', UserLdapView.as_view(), name='user-ldap-create'),
    path('<int:user_id>',UserLdapDetailView.as_view(), name='user-ldap-detail'),
]