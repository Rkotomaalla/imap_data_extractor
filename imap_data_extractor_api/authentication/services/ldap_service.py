import logging
from ldap3 import Server, Connection, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPBindError
from ldap3.utils.dn import escape_rdn
from ldap3.utils.conv import escape_filter_chars
from django.conf import settings
from connexion.service import Service
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
    def authenticate_user(self,email,password):
        """
        Authentifie un utilisateur via LDAP en utilisant son EMAIL.
        
        Args:
            email: Adresse email de l'utilisateur
            password: Mot de passe
            
        Returns:
            dict: Informations utilisateur si authentifié, None sinon
        """
        if not email or not password:
            logger.warning("Email ou mot de passe vide.")
            return None
        
        # Échapper l'email pour éviter l'injection LDAP
        email=email.strip().lower()
        safe_email = escape_filter_chars(email)
        
        ldap_service = Service()
        admin_conn = ldap_service.get_admin_connection()
        
        if not admin_conn:
            return None
        
        try:
            search_filter=f'(mail={safe_email})'
            logger.debug(f"Recherche utilisateur par email: {search_filter}")
            
            success = admin_conn.search(
                search_base=self.config['USER_BASE'],
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['uid', 'cn', 'mail', 'givenName', 'sn']
            )
            
            if not success or len(admin_conn.entries) == 0:
                logger.warning(f"⚠️ Utilisateur non trouvé avec l'email: {email}")
                admin_conn.unbind()
                return None
            
            # Vérifier qu'il n'y a qu'un seul utilisateur avec cet email
            if len(admin_conn.entries) > 1:
                logger.error(f"❌ Plusieurs utilisateurs trouvés avec l'email: {email}")
                admin_conn.unbind()
                return None
            
            user_entry = admin_conn.entries[0]
            user_dn = user_entry.entry_dn
            logger.info(f"Utilisateur trouvé: {user_dn}")
            
             # 4. Tenter la connexion avec les credentials utilisateur
            user_conn = Connection(
                self.server,
                user=user_dn,
                password=password,
                auto_bind=True,
                raise_exceptions=True
            )
            logger.info(f"Authentification réussie pour: {email}")
              # 5. Extraire les informations utilisateur
            user_info = {
                'username': user_entry.uid.value if hasattr(user_entry, 'uid') else None,
                'dn': user_dn,
                'email': user_entry.mail.value if hasattr(user_entry, 'mail') else email,
                'first_name': user_entry.givenName.value if hasattr(user_entry, 'givenName') else '',
                'last_name': user_entry.sn.value if hasattr(user_entry, 'sn') else '',
                'full_name': user_entry.cn.value if hasattr(user_entry, 'cn') else '',
            }
            
             # 6. Récupérer les rôles
            roles = self.get_user_roles(admin_conn, user_dn)
            user_info['role'] = roles[0]['name'] if roles else '' 
            
            # user_info['department'] =  self.get_user_department(admin_conn,user_dn)
            # 3. Fermer la connexion admin
            admin_conn.unbind()
            user_conn.unbind()
            
            return user_info
        except LDAPBindError:
            logger.warning(f"Mot de passe incorrect pour: {email}")
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
             
            uid = None
            for part in user_dn.split(','):
                if part.strip().lower().startswith('uid='):
                    uid = part.split('=', 1)[1].strip()
                    break
                
            if not uid:
                logger.error(f"❌ Impossible d'extraire le uid depuis: {user_dn}")
                return []
            
            # Échapper le DN pour le filtre LDAP
            escaped_uid= escape_filter_chars(uid)

            logger.debug(f"Recherche des rôles pour uid: {uid}")
            logger.debug(f" Base: {self.config['ROLE_BASE']}")
            # logger.debug(f"🔎 Filtre: (&(objectClass=posixGroup)(memberUid={escaped_uid}))")
            logger.debug(f"Connexion bound: {conn.bound}")
            logger.debug(f" Utilisateur connecté: {conn.extend.standard.who_am_i()}")
    
            
            success = conn.search(
                search_base=self.config['ROLE_BASE'],
                search_filter=f'(memberUid={escaped_uid})',
                search_scope=SUBTREE,
                attributes=['cn', 'description', 'gidNumber']
            )
            # logger.debug(f"Recherche des rôles etablies  pour: {user_dn}")
            
            if not success:
                logger.debug(f"Aucun rôle trouvé pour: {user_dn}")
                return []
            
            if len(conn.entries) == 0:
                logger.info(f"ℹ️ Recherche réussie mais 0 groupe trouvé pour: {user_dn}")
                return []
            
            # Extraire les rôles
            roles = []
            for entry in conn.entries:
                if hasattr(entry, 'cn'):
                    role = {
                        'name': entry.cn.value,
                        'description': entry.description.value if hasattr(entry, 'description') else ''
                    }
                    roles.append(role)
                    # logger.debug(f"  ✓ Rôle trouvé: {role['name']} - {role['description']}")
            
            # logger.info(f"✅ Trouvé {len(roles)} rôle(s) pour {user_dn}")
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