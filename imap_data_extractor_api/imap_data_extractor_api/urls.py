"""
URL configuration for imap_data_extractor_api project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include

from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('user/', include('authentication.urls')),
    
    path('departments/', include('departments.urls')),
    
    path('users/', include('users.urls')),
    
    path('bots/', include('bots.urls')),
    
    path('fields/', include('bot_filter.urls')),

    path('actions/',include('bot_action.urls')),
    
    path('mail/',include('mail.urls')),
    
        
    path('configuration/',include('configurations.urls')),
    
    # path('outlook/',include('outlook_integration.urls')),
    
    path('gmail/',include('mail_integration.urls')),

    path('stats/',include('stats.urls')),
    #paht pour les swaggers 
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),  # fichier OpenAPI JSON
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),  # interface Swagger UI    
]
 