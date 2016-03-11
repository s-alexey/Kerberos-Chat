import json
import os
import tornado.ioloop
import tornado.web

from kerberos.utils import get_timestamp, check_timestamp, \
    TIME_TO_LIVE_SESSION_KEY

from kerberos.tgs.models import Service
from kerberos import crypto


TGS_NAME = os.getenv('TGS_NAME', 'tgs')
TGS_KEY = os.getenv('TGS_KEY', crypto.password2key('tgs_key'))


class TicketGrantingService(tornado.web.RequestHandler):
    """
    Ticket-granting service provides Client Service Authorization.
    """

    def data_received(self, chunk):
        pass

    def __init__(self, application, request, **kwargs):
        super().__init__(application, request, **kwargs)
        self.name = TGS_NAME
        self.key = TGS_KEY

    def get(self):
        self.write("Use method POST with 'authenticator', 'tgs_ticket' and 'service'")

    def post(self):

        if not self.request.arguments:
            dump = self.request.body.decode()
            request = json.loads(dump)
            authenticator = request.get('authenticator', '')
            tgs_ticket = request.get('tgs_ticket', '')
            service = request.get('service', '')
        else:
            authenticator = self.get_argument('authenticator', '')
            tgs_ticket = self.get_argument('tgs_ticket', '')
            service = self.get_argument('service', '')

        if not authenticator:
            self.send_error(400, reason="Authenticator wasn't provided.")
            return
        if not tgs_ticket:
            self.send_error(400, reason="TGS ticket wasn't provided.")
            return

        try:
            service = Service.objects.get(name=service)
        except Service.DoesNotExist:
            self.send_error(400, reason="Service with such name doesn't exist.")
            return

        tgs_ticket = crypto.decrypt_json(tgs_ticket, self.key)

        session_key = tgs_ticket['session_key']
        authenticator = crypto.decrypt_json(authenticator, session_key)

        if authenticator['user_name'] != tgs_ticket['user_name']:
            self.send_error(400, reason="User name in ticket and authenticator don't match.")
            return

        # TODO this check sometimes doesn't work (ip is different)
        # if self.request.remote_ip != tgs_ticket['user_ip']:
        #     self.send_error(400, reason="IP-addresses in ticket and request don't match.")
        #     return

        if not check_timestamp(tgs_ticket['timestamp'],
                               tgs_ticket['tgs_ticket_time_to_live']):
            self.send_error(400, reason="TGS ticket has expired.")
            return
        if not check_timestamp(authenticator['timestamp'], ):
            self.send_error(400, reason="Authenticator ticket has expired.")
            return

        client_service_sk = crypto.generate_b64key()

        service_ticket = {
            'user_name': tgs_ticket['user_name'],
            'user_ip': tgs_ticket['user_ip'],
            'timestamp': get_timestamp(),
            'time_to_live': TIME_TO_LIVE_SESSION_KEY,
            'client_service_sk': client_service_sk,
            'service': service.name,
        }

        tgs_resp = {
            'service_ticket': crypto.encrypt_json(service_ticket, service.key),
            'service': service.name,
            'client_service_sk': client_service_sk,
            'time_to_live': TIME_TO_LIVE_SESSION_KEY,
        }

        response = crypto.encrypt_json(tgs_resp, session_key)
        self.write(response)


def make_app():
    return tornado.web.Application([
        (r"/tgs", TicketGrantingService),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
