import functools
import json
from datetime import timedelta

import tornado.web
import tornado.ioloop
import tornado.websocket
import tornado.httpserver

from kerberos import crypto
from kerberos.utils import check_timestamp, get_timestamp
from kerberos.chat.models import ChatUser, Message

UPDATE_TIMEOUT = 5


class Commands:
    LOGIN = 'login'
    ONLINE = 'online'
    NEW_MESSAGE = 'new_message'
    NEW_ROOM = 'new_room'
    GO_ROOM = 'go_room'
    SECRET = 'secret'
    DELETE_CHAT = 'delete_chat'
    SAVE_DATA = 'save_data'
    GET_DATA = 'get_data'


def fields_required(fields):
    @functools.wraps
    def decorator(f):
        def wrapper(self, message, *args, **kwargs):
            for field in fields:
                if field not in message:
                    return self.report_error(
                            "Command doesn't contain {} attribute".format(field))
            return f(self, *args, **kwargs)
        return wrapper
    return decorator


class ChatClientSocket(tornado.websocket.WebSocketHandler):
    def data_received(self, chunk):
        pass

    def __init__(self, application, request, **kwargs):
        super().__init__(application, request, **kwargs)
        self.chat = self.application.chat
        ':type kerberos.chat.server.ChatServer'
        self.previous_timestamp = get_timestamp()
        self.session_key = ''
        ':type str'
        self.update_timeout = UPDATE_TIMEOUT
        ':type int'
        self.user = None
        ':type ChatUser'

    def open(self):
        pass

    def on_message(self, message):
        if not self.user:
            message_dict = crypto.json.loads(message)
        else:
            message_dict = crypto.decrypt_json(message, self.session_key)

        if 'type' not in message_dict:
            self.report_error("Command 'type' wasn't been specified.")

        command = message_dict.pop('type')

        if not self.user:
            if command == Commands.LOGIN:
                return self.do_login(message_dict)
            else:
                return self.report_error("You are not authorized.")

        else:
            if 'from' not in message_dict:
                # self.report_error("No 'from' key in request.")
                pass
            elif self.user.name != message_dict['from']:
                self.report_error("User names are different")
            else:
                timestamp = message_dict.pop('timestamp')
                if not self.validate_timestamp(timestamp):
                    return self.report_error("Invalid timestamp")

                if command == Commands.ONLINE:
                    self.send_online()
                elif command == Commands.NEW_ROOM:
                    self.new_room(message_dict)
                elif command == Commands.NEW_MESSAGE:
                    self.new_message(message_dict)
                elif command == Commands.GO_ROOM:
                    self.go_room(message_dict)
                elif command == Commands.SECRET:
                    self.add_secret(message_dict)
                elif command == Commands.GET_DATA:
                    self.get_data(message_dict)
                elif command == Commands.SAVE_DATA:
                    self.save_data(message_dict)
                else:
                    self.report_error("Unknown command {}".format(command))

    def on_close(self):
        if self.user:
            self.chat.user_offline(self.user.name)

        if self.update_timeout:
            tornado.ioloop.IOLoop.instance().remove_timeout(self.update_timeout)

    def write_encrypted(self, dictionary):
        if 'type' not in dictionary:
            raise ValueError("Can't send message without type.")

        dictionary['timestamp'] = get_timestamp()
        dictionary['service'] = self.chat.name
        self.write_message(crypto.encrypt_json(dictionary, self.session_key))

    @fields_required(['service_ticket', 'authenticator'])
    def do_login(self, message):
        ticket = message['service_ticket']
        try:
            ticket = crypto.decrypt_json(ticket, self.chat.key)
        except Exception as e:
            self.report_error("Can't decode ticket.")
            raise e

        for key in ['client_service_sk', 'user_name', 'timestamp', 'time_to_live']:
            if key not in ticket:
                return self.report_error("Ticket doesn't contain '{}'".format(key))

        self.session_key = ticket['client_service_sk']
        username = ticket['user_name']

        if not check_timestamp(ticket['timestamp'], ticket['time_to_live']):
            return self.report_error("Ticket timestamp is very old.")

        authenticator = message['authenticator']
        try:
            authenticator = crypto.decrypt_json(authenticator, self.session_key)
        except Exception as e:
            self.report_error("Can't decrypt authenticator")
            raise e

        for key in ['timestamp', 'user_name']:
            if key not in authenticator:
                return self.report_error("Authenticator doesn't contain '{}'".format(key))

        if not check_timestamp(authenticator['timestamp'], ticket['time_to_live']):
            return self.report_error("Authenticator timestamp is very old")
        if username != authenticator['user_name']:
            return self.report_error("User names in authenticator and ticket aren't the same!")

        self.user = ChatUser.objects.get(name=username)
        self.chat.user_online(self.user.name, self)

        self.update_timeout = tornado.ioloop.IOLoop.instance().add_timeout(
            timedelta(seconds=1), self.send_online)

        self.write_encrypted({
            'service': self.chat.name,
            'type': 'handshake'
        })

    def send_online(self):
        self.update_timeout = tornado.ioloop.IOLoop.instance().add_timeout(
            timedelta(seconds=UPDATE_TIMEOUT), self.send_online)

        online_users = self.chat.get_online_users()
        rooms = self.chat.get_available_rooms(self.user)

        self.write_encrypted({
            "type": "online",
            "users_online": online_users,
            "rooms": rooms
        })

    @fields_required(['message', 'room'])
    def new_message(self, message):
        room = message['room']
        for key in ['room', 'text']:
            if key not in message['message']:
                return self.report_error("Message doesn't contain '{}' field.".format(key))
        if 'from' in message:
            if not message['from'] == self.user.name:
                return self.report_error("You can't write from other name.")

        time = message.get('time', get_timestamp())
        message = Message(user=self.user, text=message['text'],
                          time=time, room=message['room'])
        self.chat.new_message(room, message)

    @fields_required(['threshold', 'room', 'users'])
    def new_room(self, message):
        room_name, threshold = message['room'], message['threshold']

        try:
            threshold = int(threshold)
        except ValueError:
            return self.report_error("Threshold must be positive int.")

        users = message['users']
        if self.user.name not in users:
            users.append(self.user.name)

        self.chat.create_room(room_name, users, threshold)

    @fields_required(['secret', 'room'])
    def go_room(self, message):
        room = message['room']
        if isinstance(room, dict):
            room = room['name']
        secret = message['secret']

        self.chat.open_room(room, secret=secret, user=self.user.name)

    @fields_required(['secret', 'room'])
    def add_secret(self, message):
        room = message['room']
        share = message['secret']
        self.chat.add_secret(user=self.user.name, secret=share, room_id=room)

    @fields_required(['key', 'data'])
    def save_data(self, message):
        key = message['key']
        if isinstance(key, dict):
            key = key['name']
        self.user.data[key] = message['data']

    @fields_required(['key'])
    def get_data(self, message):
        key = message['key']
        if isinstance(key, dict):
            key = key['name']

        self.write_encrypted({
            'type': 'data',
            'key': key,
            'data': self.user.data.get(key, '')
        })

    def report_error(self, reason):
        report = {"type": "error", "error": reason}
        if self.user:
            self.write_encrypted(report)
        else:
            self.write(json.dumps(report))

    def validate_timestamp(self, new_timestamp):
        # TODO add sensible checker here
        self.previous_timestamp = new_timestamp
        return True


def get_app():
    return tornado.web.Application([
        (r'/path/to/websocket', ChatClientSocket)
    ])
