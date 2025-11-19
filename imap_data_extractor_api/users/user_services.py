from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPEntryAlreadyExistsResult
from ldap3.utils.hashed import hashed
import hashlib
from django.conf import settings
from connexion.service import Service
from passlib.hash import sha256_crypt  # ou bcrypt, argon2, etc.
import os
import logging
logger = logging.getLogger(__name__)

class UserService:
    def __init__(self):
        self.config=settings.LDAP_CONFIG
        self.ldap_host=self.config['SERVER']
        self.ldap_base_dn=self.config['BASE_DN']
        self.ldap_bind_dn=self.config['BIND_DN']
        self.ldap_bind_password =self.config['BIND_PASSWORD']
        self.use_ssl=self.config['USE_SSL']
        self.ldap_department_base=self.config['DEPARTMENT_BASE']
        self.server = None
        self.connection = None
        
    def _connect(self):
        """Établir la connexion LDAP avec ldap3"""
        try:
            # Créer le serveur LDAP
            self.server = Server(
                self.ldap_host,
                get_info=ALL,
                use_ssl=self.use_ssl
            )
            
            # Créer la connexion
            self.connection = Connection(
                self.server,
                user=self.ldap_bind_dn,
                password=self.ldap_bind_password,
                auto_bind=True,  # Se connecte automatiquement
                raise_exceptions=True
            )
            
            return True
            
        except LDAPBindError as e:
            raise Exception(f"Erreur d'authentification LDAP: {str(e)}")
        except LDAPException as e:
            raise Exception(f"Erreur de connexion LDAP: {str(e)}")
        except Exception:
            self._disconnect()
            return False
        
    def _disconnect(self):
        """Fermer la connexion LDAP"""
        if self.connection:
            self.connection.unbind()
            
            
    # def _hash_password(self, password):
    #     """
    #     Hasher le mot de passe en SSHA (Salted SHA) pour LDAP
    #     ldap3 fournit une fonction native pour cela
    #     """
    #     return hashed(hashlib.sha1, password, salt=16)
    
    def _hash_password(self, password):
        return sha256_crypt.hash(password)

    def set_username(self,first_name,last_name):
        """
            Fonction pour gerer les usernames 
        """
        username = f"{last_name[0].lower()}{first_name.lower()}"
        
        # a Faire Voir isi l username et valide sinon ajouter un nombre avec
        return username;
    
 
    def add_user(self, user_data, save_to_db=False):
        """
        Ajouter un utilisateur dans OpenLDAP avec ldap3
        
        Args:
            user_data (dict): Données de l'utilisateur validées
            save_to_db (bool): Si True, sauvegarde aussi dans la base Django
            
        Returns:
            dict: Résultat de l'opération
        """
        try:
            self._connect()

            username=self.set_username(user_data['first_name'],user_data['last_name'])
            
            user_dn = f"uid={username},ou={user_data['departement']},{self.ldap_department_base}"
            
            logger.info(f"Vérification de l'existence de l'utilisateur avec email:EOOOOOO")
            
            # Générer uidNumber
            uid_number = self._get_next_uid_number()
            
            # Définir les attributs LDAP
            attributes = {
                'objectClass': ['inetOrgPerson', 'posixAccount', 'top'],
                'uid': username,
                'cn': f"{user_data['first_name']} {user_data['last_name']}",
                'sn': user_data['last_name'],
                'givenName': user_data['first_name'],
                'mail': user_data['email'],
                'userPassword':user_data['password'],
                'ou': user_data['departement'],
                'description': user_data['role'],
                'uidNumber': str(uid_number),
                'gidNumber': '1000',
                'homeDirectory': f"/home/{username}",
                'loginShell': '/bin/bash'
            }
            print("DEBUG ATTRIBUTES =", attributes)
            # Ajouter l'utilisateur avec ldap3
            success = self.connection.add(user_dn, attributes=attributes)
            
            if not success:
                raise Exception(f"Échec de création: {self.connection.result}")
            
            self._disconnect()
            
            result = {
                'username': username,
                'dn': user_dn,
                'email': user_data['email'],
                'role': user_data['role'],
                'departement': user_data['departement'],
                'uid_number': uid_number
            }
            return result
            
        except LDAPEntryAlreadyExistsResult:
            self._disconnect()
            raise Exception("Un utilisateur avec ce nom existe déjà dans LDAP")
        except LDAPException as e:
            self._disconnect()
            raise Exception(f"Erreur LDAP: {str(e)}")
        except Exception as e:
            self._disconnect()
            raise Exception(f"Erreur inattendue: {str(e)}")
        
        
        
       
    def _get_next_uid_number(self):
        """
        Obtenir le prochain uidNumber disponible
        Recherche le plus grand uidNumber existant et ajoute 1
        """
        try:
            if not self.connection:
                self._connect()
                
            # Chercher tous les uidNumber existants
            self.connection.search(
                search_base=f"{self.ldap_department_base}",
                search_filter='(objectClass=posixAccount)',
                search_scope=SUBTREE,
                attributes=['uidNumber']
            )
            if not self.connection.entries:
                # Aucun utilisateur, commencer à 10000
                return 10000
            # Trouver le max uidNumber
            uid_numbers = [
                int(entry.uidNumber.value) 
                for entry in self.connection.entries 
                if hasattr(entry, 'uidNumber')
            ]
            return max(uid_numbers) + 1 if uid_numbers else 10000
        except Exception:
            # En cas d'erreur, retourner un nombre aléatoire
            import random
            return random.randint(10000, 99999)
        

    def user_exists(self, email):
        """
        Vérifier si un utilisateur existe déjà dans LDAP
        
        Args:
            email (str): Email de l'utilisateur
            
        Returns:
            bool: True si l'utilisateur existe
        """
        try:
            self._connect()
            
            # Rechercher par email
            self.connection.search(
                search_base=f"{self.ldap_department_base}",
                search_filter=f"(mail={email})",
                search_scope=SUBTREE,
                attributes=['mail']
            )
            exists = len(self.connection.entries) > 0
            self._disconnect()
            
            return exists
            
        except Exception:
            self._disconnect()
            return False
# Créer une instance globale du service
user_service =UserService()