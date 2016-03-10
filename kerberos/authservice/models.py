from mongoengine import *

import os

url = os.getenv("AS_DB_URL", 'as')
connect(url)


class Record(Document):
    meta = {
        'abstract': True,
    }
    name = StringField(unique=True)
    key = StringField()

    def __str__(self):
        return self.name

    @classmethod
    def get_key_by_name(cls, name):
        return cls.objects.get(name=name).key


class User(Record):
    pass


class TGS(Record):
    pass
