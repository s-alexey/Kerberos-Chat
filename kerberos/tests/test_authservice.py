import json

import mongoengine
import os

from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.testing import AsyncHTTPTestCase
import tornado.testing

from kerberos.tests.utils import as_request_data

from kerberos.authservice.as_handler import make_app
from kerberos.authservice.models import User, TGS
from kerberos.crypto import password2key, decrypt_json


TEST_DB_URL = os.getenv('AS_TEST_URL', 'as_test')


class AuthenticationServerTest(AsyncHTTPTestCase):

    def setUp(self):
        super().setUp()
        self.db = mongoengine.connect(TEST_DB_URL)
        self.client = AsyncHTTPClient(self.io_loop)

    def tearDown(self):
        User.objects.delete()
        TGS.objects.delete()
        self.db.drop_database(TEST_DB_URL)

    def get_app(self):
        return make_app()

    @tornado.testing.gen_test
    def test_login(self):
        user = User(name='JohnDoe', key=password2key('johndoe'))
        user.save()
        tgs = TGS(name='tgs', key=password2key('tgs'))
        tgs.save()

        request_data = as_request_data(user, tgs)

        request = HTTPRequest(self.get_url('/as/login'), method="POST",
                              headers={'Content-Type': 'application/json'},
                              body=json.dumps(request_data))

        response = yield self.client.fetch(request)
        data = decrypt_json(response.body, user.key)
        for key in ['tgs_name', 'session_key', 'tgs_ticket',
                    "tgs_ticket_time_to_live", "session_key_time_to_live"]:
            self.assertIn(key, data)

        ticket = decrypt_json(data['tgs_ticket'], tgs.key)
        for key in ['tgs_name', 'session_key', 'timestamp', 'user_name', 'user_ip',
                    "tgs_ticket_time_to_live", "session_key_time_to_live"]:
            self.assertIn(key, ticket)

        for key in ['session_key', 'tgs_name', "tgs_ticket_time_to_live",
                    "session_key_time_to_live"]:
            self.assertEqual(data[key], ticket[key], "{} don't match".format(key))

    @tornado.testing.gen_test
    def test_wrong_login(self):
        user = User(name='JohnDoe', key=password2key('johndoe'))
        # user.save()
        tgs = TGS(name='tgs', key=password2key('tgs'))
        tgs.save()

        request_data = as_request_data(user, tgs)

        request = HTTPRequest(self.get_url('/as/login'), method="POST",
                              headers={'Content-Type': 'application/json'},
                              body=json.dumps(request_data))

        with self.assertRaises(tornado.httpclient.HTTPError) as context:
            yield self.client.fetch(request)

        self.assertEqual(context.exception.code, 400)

    @tornado.testing.gen_test
    def test_wrong_tgs(self):
        user = User(name='JohnDoe', key=password2key('johndoe'))
        user.save()
        tgs = TGS(name='tgs', key=password2key('tgs'))
        # tgs.save()

        request_data = as_request_data(user, tgs)

        request = HTTPRequest(self.get_url('/as/login'), method="POST",
                              headers={'Content-Type': 'application/json'},
                              body=json.dumps(request_data))

        with self.assertRaises(tornado.httpclient.HTTPError) as context:
            yield self.client.fetch(request)

        self.assertEqual(context.exception.code, 400)

if __name__ == '__main__':
    tornado.testing.main()
