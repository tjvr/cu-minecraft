from datetime import datetime
import random
import regex
import string
from urllib import quote, urlencode

import requests
from peewee import *



POSTGRES_PASSWORD = '' # TODO sane config
INITIAL_ADMINS = {} # our CRSid

db = PostgresqlDatabase('minecraft', user='minecraft', password=POSTGRES_PASSWORD)
db.get_conn().set_client_encoding('UTF8')
#db = SqliteDatabase('../cumc.db')


class BaseModel(Model):
    class Meta:
        database = db

    def __repr__(self):
        return "<%s(%r)>" % (self.__class__.__name__, str(self))


#-------------------------------------------------------------------------------

class MinecraftInfo(BaseModel):
    MOJANG_API = "https://api.mojang.com/"

    username = CharField(max_length=16)
    uuid = CharField(max_length=32)
    last_login = DateTimeField(null=True)
    online = BooleanField(default=False)

    NAME_RE = regex.compile(r'[a-zA-Z0-9_]+')

    def __str__(self):
        return self.username

    @classmethod
    def get_by_username(cls, username):
        path = '/users/profiles/minecraft/{}'.format(quote(username))
        r = requests.get(cls.MOJANG_API + path)
        try:
            d = r.json()
        except ValueError:
            return
        try:
            info = MinecraftInfo.get(uuid=d['id'])
            info.username = d['name']
            info.save()
        except MinecraftInfo.DoesNotExist:
            info = MinecraftInfo.create(uuid=d['id'], username=d['name'])
        return info

    def get_name_history(self):
        path = '/user/profiles/{}/names'.format(quote(self.uuid))
        r = requests.get(self.MOJANG_API + path)
        name_changes = r.json()
        return [(d['name'], d.get('changedAt', 0))
                for d in name_changes]

    def refresh_username(self):
        new_username, changed_at = self.get_name_history()[-1]
        if self.username != new_username:
            self.username = username
            self.save()
            return True
        return False

    def avatar(self, kind='avatar', size=None):
        api = "https://crafatar.com"
        path = {
            'avatar': "avatars",
            'body': "renders/body",
        }[kind]
        url = "https://crafatar.com/{}/{}/?{}".format(
            path,
            quote(self.uuid),
            urlencode(dict(size=str(size))) if size else "",
        )
        return url



InviteProxy = Proxy()

class Person(BaseModel):
    is_admin = BooleanField(default=False)
    invite = ForeignKeyField(InviteProxy, null=True)
    real_name = CharField(max_length=100, default="")

    created_time = DateTimeField(default=datetime.now)
    last_visit = DateTimeField(null=True)

    has_joined = BooleanField(default=False)
    join_time = DateTimeField(null=True)
    signature = TextField(default="")

    minecraft = ForeignKeyField(MinecraftInfo, null=True)

    def __str__(self):
        return self.real_name

    @property
    def first_name(self):
        words = self.real_name.split(" ")
        return words[0] if words else ""

class Invite(Person):
    invited_by = ForeignKeyField(Person)

InviteProxy.initialize(Invite)


class Server(BaseModel):
    name = CharField(max_length=50)
    address = CharField(max_length=50)

    def __str__(self):
        return self.address

#-------------------------------------------------------------------------------

# NB. anonymous Lookup only works inside the CUDN
def get_real_name(crsid):
    base = 'https://anonymous:@www.lookup.cam.ac.uk/api/v1'
    path = '/person/crsid/{}?format=json'.format(quote(crsid))
    url = base + path
    r = requests.get(url)
    return r.json().get('result', {}).get('person', {}).get('visibleName', "")

class RavenAuth(BaseModel):
    person = ForeignKeyField(Person, unique=True, related_name='raven_auths')
    created_time = DateTimeField(default=datetime.now)
    principal = CharField(max_length=100)
    real_name = CharField(max_length=200)

    def __str__(self):
        return self.principal

#-------------------------------------------------------------------------------

def random_token():
    # base 52
    N = 16
    return ''.join(random.choice(string.ascii_letters)
                   for _ in range(N))

class EmailAuth(BaseModel):
    person = ForeignKeyField(Person, unique=True, related_name='email_auths')
    email = CharField(max_length=100, unique=True)

    def __str__(self):
        return self.email

class AuthToken(BaseModel):
    auth = ForeignKeyField(EmailAuth)
    token = CharField(default=random_token, max_length=32)

AUTH_TYPES = dict((cls.__name__, cls) for cls in [
    RavenAuth, EmailAuth,
])

#-------------------------------------------------------------------------------

def first_time_setup():
    MinecraftInfo.create_table()
    Person.create_table()
    Invite.create_table()
    RavenAuth.create_table()
    EmailAuth.create_table()
    AuthToken.create_table()
    Server.create_table()

    for crsid in INITIAL_ADMINS:
        real_name = 'Tim' #get_real_name(crsid)
        person = Person.create(is_admin=True, real_name=real_name)
        RavenAuth.create(person=person, principal=crsid, real_name=real_name)

    Server.create(name="Modded PvE", address="minecraft-host.example.com")

