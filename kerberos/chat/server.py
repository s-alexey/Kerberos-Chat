import os

import tornado

from kerberos.chat.models import Room, ChatUser
from kerberos import crypto
from kerberos.secretsharing.sharing import SecretSharer

SERVICE_NAME = os.getenv('SERVICE_NAME', 'chat')
SERVICE_KEY = os.getenv('SERVICE_KEY', crypto.password2key('service_key'))

DEFAULT_SECRET_MODULE = 2 ** 320
SECRET_MODULE = os.getenv('SECRET_MODULE', DEFAULT_SECRET_MODULE)


class ChatServer:
    def __init__(self):
        self.webSocketsPool = []
        self.online_users = dict()
        self.active_rooms = {}
        self.messages_send = set()
        self.key = SERVICE_KEY
        self.name = SERVICE_NAME

    def user_online(self, user, socket):
        """
        Make user online.
        :param user: user to add
        :type user: kerberos.chat.models.ChatUser
        :param socket: socket connection with user
        :type socket: kerberos.chat.clientsocket.ChatClientSocket
        :return:
        """
        if user in self.online_users:
            # TODO add support for multiple device login
            return socket.report_error("You are already online!")

        self.online_users[user] = socket

    def user_offline(self, user):
        if user not in self.online_users:
            raise ValueError("Cannot remove user. User already offline.")
        self.online_users.pop(user)

    def get_online_users(self):
        return list(self.online_users.keys())

    def check_rooms(self):
        """
        Check, whether are currently opened room can be still opened.
        :return: None
        """
        online = set(self.online_users.keys())

        temp_rooms = set()
        for room_id, room in self.active_rooms.items():
            if len(set(room.get_users()).intersection(online)) < room.get_threshold():
                temp_rooms.add(room_id)

        for room in temp_rooms:
            self.notify_users(room.users, {
                'type': 'close_room',
                'room': room.room_id
            })
            self.active_rooms.pop(room.room_id)

    def notify_users(self, users, dictionary):
        for user in users:
            self.notify_user(user, dictionary)

    def notify_user(self, user, dictionary):
        if user in self.online_users:
            self.online_users[user].write_encrypted(dictionary)

    def get_available_rooms(self, user):
        result = []
        users = set(self.get_online_users())

        for room in Room.objects:
            # if users representation change it will broke
            users_in_room = set(room.users)
            if user in users_in_room:
                if len(users_in_room.intersection(users)) >= room.threshold:
                    result.append(Room(room))

        return result

    def get_room(self, room_id):
        if isinstance(room_id, dict):
            room_id = room_id['room']
        else:
            room_id = room_id

        if room_id not in self.active_rooms:
            # if it isn't yet opened we nevertheless can open it
            room = Room.objects.get(room_id=room_id)
            if room.threshold == 0:
                self.active_rooms[room_id] = room
            else:
                raise ValueError("Can't get room. Room is closed.")
        return self.active_rooms[room_id]

    def close_room(self, room):
        if isinstance(room, dict):
            room_key = room['room']
        else:
            room_key = room
        self.active_rooms.pop(room_key)

    def create_room(self, name, users, threshold):

        users = ChatUser.objects.filter(user_in=users)
        room = Room(name=name, users=users, threshold=threshold).save()

        invite = {
            "type": "new_room",
            "room": room.to_json()
        }
        secret = crypto.generate_b64key()
        if threshold == 0:
            shares = [''] * len(users)
        elif threshold == 1:
            shares = [secret] * len(users)
        else:
            shares, module = SecretSharer.split_secret(secret, threshold,
                                                       len(users), SECRET_MODULE)
        for share, user in zip(shares, users):
            invite['secret'] = share
            room.secret_shares[user] = secret
            self.notify_user(user, invite)

    def open_room(self, name, user=None, secret=None):
        if name in self.active_rooms and self.get_room(name).is_available() and user:
            # room has been opened, send messages
            return self.room_messages(name, user)
        elif name in self.active_rooms and self.get_room(name).is_available():
            # room
            raise ValueError("Room is already opened.")
        elif name not in self.active_rooms:
            self.active_rooms[name] = Room.objects.filter(room_id=name)

        room = self.active_rooms[name]

        if room.get_threshold() == 0:
            self.room_messages(room)
            return

        users = room.get_users().copy()

        if user and secret:
            if self.add_secret(user, room.get_name(), secret):
                return
            users.remove(user)

        invite = {
            "type": "get_secret",
            "room": room.info()
        }

        self.notify_users(users, invite)

    def add_secret(self, user, room_id, secret):
        room = self.get_room(room_id)
        room.add_secret_share(user=user, share=secret)

        if room.is_available():
            if room not in self.messages_send:
                self.room_messages(room)
                self.messages_send.add(room)
            return True

        return False

    def room_messages(self, room_id, users=None):
        if isinstance(room_id, dict):
            room_id = room_id['name']

        room = Room.objects.get(room_id=room_id)

        notification = {
            "type": "room_messages",
            "room": room.name,
            "messages": room.get_messages()
        }
        self.notify_users(room.users, notification)

    def new_message(self, room_id, message):
        """ Store and notify users in room about new message.
        :param room_id:
        :param message:
        :type kerberos.chat.models.Message
        :return:
        """
        room = self.get_room(room_id)
        room.messages.append(message)
        room.save()

        notification = {
            "type": "new_message",
            "new_message": message,
        }
        self.notify_users(room.users, notification)


def make_app():
    from kerberos.chat.clientsocket import ChatClientSocket

    class ChatApplication(tornado.web.Application):
        def __init__(self):
            self.chat = ChatServer()
            handlers = (
                (r'/chat', ChatClientSocket),
            )
            tornado.web.Application.__init__(self, handlers)

    return ChatApplication()
