import datetime
import os

from mongoengine import *

from secretsharing.sharing import SecretSharer
from kerberos.crypto import decrypt, encrypt


db_url = os.getenv("CHAT_DB_URL", "chat")
connect(db_url)


class UserData(EmbeddedDocument):
    key = StringField()
    data = StringField()

    def __str__(self):
        return self.key


class ChatUser(Document):
    name = StringField(unique=True)
    data = DictField()

    def __str__(self):
        return self.name


class Message(EmbeddedDocument):
    user = ReferenceField(ChatUser, required=True)
    text = StringField()
    date = DateTimeField(default=datetime.datetime.now)

    def __str__(self):
        return '{}: {}'.format(self.user, self.text)


class Room(Document):
    room_id = IntField(unique=True)
    name = StringField(min_length=2, required=True)
    users = ListField(ReferenceField(ChatUser))

    # Shamir's Secret Sharing
    threshold = IntField(min_value=0)
    secret_shares = DictField()
    secret = StringField()

    messages = EmbeddedDocumentListField(Message)
    opened = BooleanField()

    @property
    def shares(self):
        return list(self.secret_shares.values())

    def __str__(self):
        return '{}, {}'.format(self.room_id, self.name)

    def is_available(self):
        if len(self.shares) >= self.threshold:
            self.opened = True
            if not self.secret:
                self.compute_secret()
        else:
            self.opened = False
            self.secret = None

        self.save()
        return self.opened

    def get_messages(self):
        if not self.threshold:
            return [message.to_json() for message in self.messages]
        elif self.threshold > 0 and self.secret:
            messages = []
            for message in self.messages:
                message = message.to_json()
                message['text'] = decrypt(message['text'], self.secret)
                message.append(message)

            return messages

    def append_message(self, message):
        if self.threshold and self.secret:
            message.text = encrypt(message.text, self.secret)
            self.messages.append(message)
            self.save()

    def compute_secret(self):
        if self.threshold == 1 and self.secret_shares:
            self.secret = self.shares[0]
        else:
            self.secret = SecretSharer.recover_secret(
                list(self.shares)[:self.threshold])

    def remove_user(self, user):
        if isinstance(user, str):
            user = ChatUser.objects.get(name=user)

        if self.room['threshold'] > len(self.room['users']):
            self.users.remove(user)
            self.pop_user_share(user)
        else:
            self.delete()

    def get_threshold(self):
        return self.room['threshold']

    def pop_user_share(self, user):
        self.secret_shares.pop(user, None)
        self.is_available()


