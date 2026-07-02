from config import OTX_API_KEY
from otx_client import consultar_otx

resultado = consultar_otx("8.8.8.8", OTX_API_KEY)
print(resultado)
