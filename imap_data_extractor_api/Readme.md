# Créer un environnement virtuel
python -m venv venv
venv\Scripts\activate  # Windows

# Installer les dépendances
pip install django djangorestframework ldap3 django-cors-headers python-decouple

# Créer le projet
django-admin startproject ldap_auth_project
cd ldap_auth_project

# Créer l'application
python manage.py startapp authentication


python manage.py makemigrations
python manage.py migrate
python manage.py createsuperuser  # Pour l'admin Django
    _> Username: admin
        Email address: krakotomalala0@gmail.com
        Password: admin