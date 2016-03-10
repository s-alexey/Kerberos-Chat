import os
from mongoengine import connect

from kerberos.authservice.models import Record

url = os.getenv('TGS_DB_URL', 'tgs')
connect(url)


class Service(Record):
    pass
