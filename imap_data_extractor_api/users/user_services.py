from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_ADD,MODIFY_DELETE,MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException, LDAPBindError, LDAPEntryAlreadyExistsResult,LDAPAttributeOrValueExistsResult
from ldap3.utils.hashed import hashed
import hashlib
from django.conf import settings
from connexion.service import Service
import traceback

from authentication.services.ldap_service import ldap_Service
# from passlib.hash import sha256_crypt  # ou bcrypt, argon2, etc.
# import os
import logging
logger = logging.getLogger(__name__)

class UserService:
    
    def __init__(self):
        self.config=settings.LDAP_CONFIG
        self.ldap_host=self.config['SERVER']
        self.ldap_base_dn=self.config['BASE_DN']
        self.ldap_bind_dn=self.config['BIND_DN']
        self.ldap_bind_password =self.config['BIND_PASSWORD']
        self.ldap_role_base=self.config['ROLE_BASE']
        self.use_ssl=self.config['USE_SSL']
        self.ldap_department_base=self.config['DEPARTMENT_BASE']
        self.server = None
        self.connection = None
        
        
# ===================================Connection LDAP===================================
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
            
            
# ===================================Mains Methods=================================== 
        
    def update_user(self, update_data,user_id,is_admin=False):
        """
        Mettre à jour un utilisateur dans LDAP
        
        Args:
            username (str): Username de l'utilisateur
            updates (dict): Champs à mettre à jour
            
        Returns:
            bool: True si succès
        """
        try:
            user=self.get_user_by_id(user_id)
            user_dn=user['dn']
            changes={}
            if 'email' in update_data:
                changes['mail']=[(MODIFY_REPLACE,[update_data['email']])]
            if 'new_password' in update_data:
                user_info = ldap_Service.authenticate_user(user['email'],update_data['current_password'])
                if user_info is  None:
                    raise Exception (f"votre mot de pass actuel est incorrect")
                else:
                    changes["userPassword"]=[(MODIFY_REPLACE,[update_data['new_password']])]
            if is_admin:
                if 'role' in update_data:
                    self.switch_user_role(user,update_data["role"])
                    changes["description"]=[(MODIFY_REPLACE,[update_data['role']])]
                if 'departement' in update_data:
                    changes["ou"]=[(MODIFY_REPLACE,[update_data['departement']])]
                    self.switch_user_department(user,update_data['departement'])   
                    user_dn=f"uid={user['username']},ou={update_data['departement']},{self.ldap_department_base}"                 

            self._connect()
            # Appliquer les modifications
            success = self.connection.modify(user_dn, changes)
            
            self._disconnect()
            return success
        
        except Exception as e:
            self._disconnect()
            print(traceback.format_exc())
            raise Exception(f"Erreur lors de la mise à jour: {str(e)}")
            
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
        

    def get_user_by_id(self, user_id):
        """
        Récupérer un utilisateur par son uidNumber (ID numérique LDAP)
        
        Args:
            user_id (int|str): uidNumber de l'utilisateur (ex: 10001)
            
        Returns:
            dict: Informations de l'utilisateur ou None
        """
        try:
            self._connect()
            
            # Manao Recherche a partir an i UIdNumber
            self.connection.search( 
                    search_base=f"{self.ldap_department_base}",
                    search_filter=f"(uidNumber={user_id})",
                    search_scope=SUBTREE,
                    attributes=['*']
            )
            if not self.connection.entries:
                self._disconnect()
                return None
            
            entry = self.connection.entries[0]
            
            user = {
                'uid_number': entry.uidNumber.value if hasattr(entry, 'uidNumber') else None,
                'username': entry.uid.value if hasattr(entry, 'uid') else None,
                'full_name': entry.cn.value if hasattr(entry, 'cn') else None,
                'first_name': entry.givenName.value if hasattr(entry, 'givenName') else None,
                'last_name': entry.sn.value if hasattr(entry, 'sn') else None,
                'email': entry.mail.value if hasattr(entry, 'mail') else None,
                'role': entry.description.value if hasattr(entry, 'description') else None,
                'departement': entry.ou.value if hasattr(entry, 'ou') else None,
                'dn': entry.entry_dn
            }
            
            self._disconnect()
            return user
        except Exception as e:
            self._disconnect()
            raise Exception(f"Erreur lors de la recherche par ID: {str(e)}")


    def list_users(self,role=None,department=None):
        """
        Lister les utilisateurs depuis LDAP
        
        Args:
            role (str): Filtrer par rôle (optionnel)
            departement (str): Filtrer par département (optionnel)
            
        Returns:
            list: Liste des utilisateurs
        """
        
        try: 
            self._connect()
            
            
            search_filter = '(objectClass=inetOrgPerson)'
            if role:
                search_filter = f"(&(objectClass=inetOrgPerson)(description={role}))"
            if department:
                search_filter = f"(&(objectClass=inetOrgPerson)(ou={department}))"
            if role and department:
                search_filter = f"(&(objectClass=inetOrgPerson)(description={role})(ou={department}))"
                
            # Rechercher les utilisateurs
            self.connection.search(
                search_base=f"{self.ldap_department_base}",
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['uid', 'cn', 'mail', 'givenName', 'sn', 'ou', 'description', 'uidNumber','gidNumber']
            )
            
            users = []
            for entry in self.connection.entries:
                users.append({
                    'uid_number': entry.uidNumber.value if hasattr(entry, 'uidNumber') else None,
                    'username': entry.uid.value if hasattr(entry, 'uid') else None,
                    'full_name': entry.cn.value if hasattr(entry, 'cn') else None,
                    'first_name': entry.givenName.value if hasattr(entry, 'givenName') else None,
                    'last_name': entry.sn.value if hasattr(entry, 'sn') else None,
                    'email': entry.mail.value if hasattr(entry, 'mail') else None,
                    'role': entry.description.value if hasattr(entry, 'description') else None,
                    'departement': entry.ou.value if hasattr(entry, 'ou') else None,
                    'gid_number' : entry.gidNumber.value if hasattr(entry,'gidNumber') else None,
                    'dn': entry.entry_dn
                })
            
            self._disconnect()
            return users
        except LDAPException as e:
            self._disconnect()
            raise Exception(f"Erreur lors de la recherche: {str(e)}")
    def delete_user(self,user_id):
        """
        Supprimer un utilisateur de LDAP
        
        Args:
            user_id (str):l uidNumber  de l'utilisateur
            
        Returns:
            bool: True si succès
        """
        try:
            user=self.get_user_by_id(user_id)
            if not user:
                raise Exception("Utilisateur non trouvé")
            user_dn=user['dn']
            if not self.set_user_role_posix_group(user,False):
                self._disconnect()
                raise Exception("Suppression du rôle de l user echoue")
            
            self._connect()
            
            success=self.connection.delete(user_dn) 
            self._disconnect()
            return success
        except LDAPException as e:
            self._disconnect()
            traceback.print_exc()   # 🔥 affiche toute la trace complète
            raise Exception(f"Erreur lors de la suppression: {str(e)}")
        

        
        # def _hash_password(self, password):
    #     """
    #     Hasher le mot de passe en SSHA (Salted SHA) pour LDAP
    #     ldap3 fournit une fonction native pour cela
    #     """
    #     return hashed(hashlib.sha1, password, salt=16)
    
    # def _hash_password(self, password):
    #     return sha256_crypt.hash(password)

    def set_username(self,first_name,last_name):
        """
            Fonction pour gerer les usernames 
        """
        username = f"{last_name[0].lower()}{first_name.lower()}"
        
        # a Faire Voir isi l username et valide sinon ajouter un nombre avec
        return username;

    def switch_user_department(self,user,new_department):
        self._connect()
         
        result = self.connection.modify_dn(
            dn=f'uid={user['username']},ou={user['departement']},{self.ldap_department_base}',
            relative_dn=f'uid={user['username']}',
            delete_old_dn=True,
            new_superior=f'ou={new_department},{self.ldap_department_base}'  # Mettre à jour avec la nouvelle unité organisationnelle
        )
        if not result:
            print(self.connection.result)
            raise Exception ("Erreur lors du changement de département")
        self._disconnect()
    
    
    def switch_user_role(self,user,new_role):
        """
            interchanger le role d un utilisateur
        """
        # supprimer ilay taloha
        if not self.set_user_role_posix_group(user,False):
            raise Exception ("Suppression du role recent non effectué dans la fonction switch_user_role")
        # ajouter na ilay vaovao
        if not self.set_user_role_posix_group(user,True,new_role):
            raise Exception ("Ajout du nouveau role  non effectué dans la fonction switch_user_role")
        
        
    def set_user_role_posix_group(self,user,is_adding=True,new_role = None):
        """
            fonction qui ajoute l utilsateur dans soit admin soit utilisateur
        """
        self._connect()
        # print("DEBUG ROLE =", user.role)
        group_dn = f"cn={user['role']},{self.ldap_role_base}" if new_role is None else f"cn={new_role},{self.ldap_role_base}" 
        if is_adding:
        # On ajoute les deux attributs en même temps (posix + groupOfNames)
            changes = {
                'memberUid': [(MODIFY_ADD, [user['username']])],
            }
        else:
            changes = {
                'memberUid': [(MODIFY_DELETE, [user['username']])],
            }    
        logger.info(f"Modifying group {group_dn} for user {user['username']}: {'adding' if is_adding else 'removing'}")
        try:
            result = self.connection.modify(group_dn, changes)
            if result:
                return True
            else:
                print(f"Échec LDAP : {self.connection.result}")
                return False

        except LDAPAttributeOrValueExistsResult:
            # Déjà membre → c'est OK, on retourne True ou False selon ton besoin
            return False  # ou True si tu considères "déjà présent" comme succès

        except LDAPException as e:
            print(f"Erreur LDAP : {e}")
            return False

        finally:
            self.connection.unbind()  # toujours fermer la connexion proprement
       
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