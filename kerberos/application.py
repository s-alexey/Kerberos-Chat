import tornado.web
import tornado.ioloop
import tornado.websocket
import tornado.httpserver

from kerberos.authservice.as_handler import AuthenticationServer
from kerberos.tgs.tgs import TicketGrantingService
from kerberos.chat.clientsocket import ChatClientSocket

from kerberos.chat.server import ChatServer


class Application(tornado.web.Application):
    def __init__(self):
        self.chat = ChatServer()
        handlers = (
            (r"/as/login", AuthenticationServer),
            (r"/tgs", TicketGrantingService),
            (r'/chat', ChatClientSocket),
        )

        tornado.web.Application.__init__(self, handlers)


application = Application()

if __name__ == "__main__":
    application.listen(8800, address='127.0.0.1')
    application.settings['debug'] = True
    tornado.ioloop.IOLoop.instance().start()
