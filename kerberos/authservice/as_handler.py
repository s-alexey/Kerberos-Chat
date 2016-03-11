import json

import tornado.ioloop
import tornado.web

from kerberos.utils import get_timestamp, TIME_TO_LIVE_SESSION_KEY, \
    TIME_TO_LIVE_TGS_TICKET
from kerberos.authservice.models import TGS, User

from kerberos import crypto


class AuthenticationServer(tornado.web.RequestHandler):
    """
    This class handles Client Authentication.
    """
    def __init__(self, application, request, **kwargs):
        super().__init__(application, request, **kwargs)
        self.user = None
        ":type User"
        self.tgs = None
        ":type TGS"

    def get(self):
        self.write("Use method POST with 'login' and 'tgs'")

    def post(self):

        if not self.request.arguments:
            dump = self.request.body.decode()
            request = json.loads(dump)
            login = request.get('login', '')
            encrypted = request.get('encrypted', '')
        else:
            login = self.get_argument('login', '')
            encrypted = self.get_argument('encrypted', '')

        if not encrypted or not login:
            self.send_error(status_code=400, reason="Encrypted or login wasn't provided.")

        try:
            self.user = User.objects.get(name=login)
        except User.DoesNotExist:
            self.send_error(status_code=400, reason="User with such login doesn't exist.")
            return

        decrypted_json = crypto.decrypt_json(encrypted, self.user.key)

        response = self.generate_response(decrypted_json)

        self.set_header("Content-Type", "application/json")
        self.write(response)

    def create_tgs_ticket(self, session_key):
        json_dict = {
            "session_key": session_key,
            "user_name": self.user.name,
            "user_ip": self.request.remote_ip,
            "tgs_name": self.tgs.name,
            "tgs_ticket_time_to_live": TIME_TO_LIVE_TGS_TICKET,
            "session_key_time_to_live": TIME_TO_LIVE_SESSION_KEY,
            "timestamp": get_timestamp()
        }

        return crypto.encrypt_json(json_dict, self.tgs.key)

    def generate_response(self, decrypted_json):
        """
        :param decrypted_json: decrypted ticket from user
        :type decrypted_json: dict
        :return: encrypted response
        """
        session_key = crypto.generate_b64key()
        try:
            self.tgs = TGS.objects.get(name=decrypted_json["tgs_name"])
        except TGS.DoesNotExist:
            raise tornado.web.HTTPError(400)

        ticket = self.create_tgs_ticket(session_key)

        response = {
            "session_key": session_key,
            "tgs_ticket": ticket,
            "tgs_ticket_time_to_live": TIME_TO_LIVE_TGS_TICKET,
            "session_key_time_to_live": TIME_TO_LIVE_SESSION_KEY,
            "tgs_name": self.tgs.name
        }

        return crypto.encrypt_json(response, self.user.key)


def make_app():
    return tornado.web.Application([
        (r"/as/login", AuthenticationServer),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
