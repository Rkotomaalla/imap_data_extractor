from connexion.service import Service
import logging
from ldap3 import Server, Connection, ALL, SUBTREE,LEVEL
from ldap3.utils.conv import escape_filter_chars
from ldap3.core.exceptions import LDAPException, LDAPBindError
from django.conf import settings

logger = logging.getLogger(__name__)    

class LDAPService:
    def __init__(self):
        pass
    
    def get_all(self):
        """
        Récupère tous les départements depuis le serveur LDAP.
        
        Returns:
            list: Liste des départements
        """
        ldap_service = Service()
        admin_conn = ldap_service.get_admin_connection()
        
        if not admin_conn:
            return []
        
        try:
            search_filter = '(ou=*)'
            logger.debug(f"Recherche des départements avec le filtre: {search_filter}")
            
            success = admin_conn.search(
                search_base=settings.LDAP_CONFIG['DEPARTMENT_BASE'],
                search_filter=search_filter,
                search_scope=LEVEL,
                attributes=['ou']
            )
            
            if not success:
                logger.warning("⚠️ Aucun département trouvé dans LDAP.")
                admin_conn.unbind()
                return []
            
            departments = []
            for entry in admin_conn.entries:
                dept_info =  entry.ou.value
                
                departments.append(dept_info)
            
            admin_conn.unbind()
            return departments
        
        except LDAPException as e:
            logger.error(f"Erreur LDAP lors de la récupération des départements: {e}")
            return []