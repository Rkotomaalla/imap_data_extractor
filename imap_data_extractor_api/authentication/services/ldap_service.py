import logging
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.utils.dn import escape_rdn
from django.conf import settings

logger = logging.getLogger(__name__)

class LDAPService:
    """Service pour gérer les connexions et opérations LDAP"""
    
    def __init__(self):
        self.config = settings.LDAP_CONFIG
        self.server = Server(
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
        
    def authenticate_user(self,username,password):
        """
        Authentifie un utilisateur via LDAP.
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe
            
        Returns:
            dict: Informations utilisateur si authentifié, None sinon
        """
        if not username or not password:
            logger.warning("Nom d'utilisateur ou mot de passe vide.")
            return None
        
        # Échapper le username pour éviter l'injection LDAP
        safe_username = escape_rdn(username)
        
    # 1. Connexion admin pour rechercher l'utilisateur
        admin_conn = self.get_admin_connection()
        if not admin_conn:
            return None
        
        try:
            search_filter= self.config['USER_FILTER'].format(username=safe_username)
            logger.debug(f"Recherche utilisateur: {search_filter}")
            
            success= admin_conn.search(
                search_base=self.config['USER_BASE'],
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['uid', 'cn', 'mail', 'givenName', 'sn']
            )
            if not success or len(admin_conn.entries) == 0:
                logger.warning(f"Utilisateur non trouvé: {username}")
                admin_conn.unbind()
                return None
            user_entry = admin_conn.entries[0]
            user_dn = user_entry.entry_dn
            logger.info(f"Utilisateur trouvé: {user_dn}")
            
            # 3. Fermer la connexion admin
            admin_conn.unbind()
            # 4. Tenter la connexion avec les credentials utilisateur
            user_conn = Connection(
                self.server,
                user=user_dn,
                password=password,
                auto_bind=True,
                raise_exceptions=True
            )
            logger.info(f"Authentification réussie pour: {username}")
            
             # 5. Extraire les informations utilisateur
            user_info = {
                'username': user_entry.uid.value if hasattr(user_entry, 'uid') else username,
                'dn': user_dn,
                'email': user_entry.mail.value if hasattr(user_entry, 'mail') else None,
                'first_name': user_entry.givenName.value if hasattr(user_entry, 'givenName') else '',
                'last_name': user_entry.sn.value if hasattr(user_entry, 'sn') else '',
                'full_name': user_entry.cn.value if hasattr(user_entry, 'cn') else '',
            }
             # 6. Récupérer les rôles
            user_info['roles'] = self.get_user_roles(user_conn, user_dn)
            
            user_conn.unbind()
            
            return user_info
        except LDAPBindError:
            logger.warning(f"Mot de passe incorrect pour: {username}")
            return None
        except LDAPException as e:
            logger.error(f"Erreur LDAP lors de l'authentification: {e}")
            return None
        finally:
            if admin_conn.bound:
                admin_conn.unbind()
                
                
    def get_user_roles(self,conn, user_dn):
        """
        Récupère les rôles d'un utilisateur.
        
        Args:
            conn: Connexion LDAP active
            user_dn: DN de l'utilisateur
            
        Returns:
            list: Liste des rôles
        """
        if not conn or not conn.bound:
            logger.error("Connexion LDAP non active")
            return []
        try:
            safe_dn = escape_rdn(user_dn)
            success = conn.search(
                search_base=self.config['ROLE_BASE'],
                search_filter=f'(member={safe_dn})',
                search_scope=SUBTREE,
                attributes=['cn', 'description']
            )
            if not success:
                logger.debug(f"Aucun rôle trouvé pour: {user_dn}")
                return []
            roles = [
                {
                    'name': entry.cn.value,
                    'description': entry.description.value if hasattr(entry, 'description') else ''
                }
                for entry in conn.entries if hasattr(entry, 'cn')
            ]
            logger.info(f"Trouvé {len(roles)} rôle(s) pour {user_dn}")
            return roles
        
        
        except LDAPException as e:
            logger.error(f"Erreur lors de la récupération des rôles: {e}")
            return []
        
        
        
    def test_connection(self):
        """
        Test la connexion au serveur LDAP.
        
        Returns:
            bool: True si connexion OK
        """
        conn = self.get_admin_connection()
        if conn:
            conn.unbind()
            return True
        return False