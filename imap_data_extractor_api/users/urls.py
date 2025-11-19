from django.urls import path
from .views import(
    UserLdapCreateView
)

urlpatterns = [
    path('', UserLdapCreateView.as_view(), name='user-ldap-create'),
]