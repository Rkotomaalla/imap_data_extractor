import logging
from ldap3 import Server, Connection,ALL
from ldap3.core.exceptions import LDAPBindError, LDAPException

from django.conf import settings

logger=logging.getLogger(__name__)

class Service :
    def __init__(self):
        self.config=settings.LDAP_CONFIG
        self.server=Server(
             self.config['SERVER'],
            get_info=ALL,
            connect_timeout=self.config['TIMEOUT']
        )
        
    def get_admin_connection(self):
        """
        Crée une connexion LDAP avec les credentials admin.
        
        Returns:
            Connection: Connexion LDAP ou None en cas d'erreur
        """
        try:
            conn = Connection (
                self.server,
                user=self.config['BIND_DN'],
                password=self.config['BIND_PASSWORD'],
                auto_bind=True,
                raise_exceptions=True
            )
            logger.info("Connexion LDAP admin réussie.")
            return conn
        except LDAPBindError as e:
            logger.error(f"Échec de la connexion LDAP admin: {e}")
            return None
        except LDAPException as e:
            logger.error(f"Erreur LDAP lors de la connexion admin: {e}")
            return None