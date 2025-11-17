from django.db import models

# Create your models here.
from django.contrib.auth.models import AbstractUser


class LDAPUser(AbstractUser):
    """
    Modèle utilisateur synchronisé avec LDAP.
    Stocke les informations en cache de la session LDAP.
    """
    
    ldap_dn = models.CharField(
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        verbose_name="Distinguished Name LDAP",
        help_text="DN complet de l'utilisateur dans LDAP"
    )
    # Ajout du role indice 0 
    ldap_role = models.CharField(    
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        verbose_name="Role LDAP",
        help_text="Le role d un utilisateur dans ldap"
    )
    
    
    ldap_roles = models.JSONField(
        default=list,
        blank=True,
        verbose_name="Rôles LDAP",
        help_text="role récupérés depuis LDAP"
    )
    
    ldap_cn=models.CharField(        
        max_length=255,
        unique=True,
        blank=True,
        null=True,
        verbose_name="Distinguished Name LDAP"
    )
    

    
    last_ldap_sync = models.DateTimeField(
        auto_now=True,
        verbose_name="Dernière synchronisation LDAP"
    )
    
    class Meta:
        verbose_name = "Utilisateur LDAP"
        verbose_name_plural = "Utilisateurs LDAP"
        db_table = 'auth_ldap_user'
        
    def __str__(self):
        return f"{self.username} ({self.email})"
    
    def has_ldap_role(self, role_name):
        """Vérifie si l'utilisateur a un rôle spécifique"""
        if not self.ldap_role:
            return False
        return any(role.get('name') == role_name for role in self.ldap_roles)