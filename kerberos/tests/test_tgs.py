import json

import mongoengine
import os

from tornado.httpclient import AsyncHTTPClient, HTTPRequest
from tornado.testing import AsyncHTTPTestCase
import tornado.testing

from kerberos import crypto
from kerberos.authservice.models import User, TGS
from kerberos.tests.utils import tgs_request_data

from kerberos.tgs.tgs import make_app, TGS_KEY, TGS_NAME
from kerberos.tgs.models import Service
from kerberos.crypto import decrypt_json


TEST_DB_URL = os.getenv('TGS_TEST_URL', 'tgs_test')


class TGSTest(AsyncHTTPTestCase):

    def clear_database(self):
        Service.objects.delete()
        User.objects.delete()
        TGS.objects.delete()

    def setUp(self):
        super().setUp()
        self.db = mongoengine.connect(TEST_DB_URL)
        self.clear_database()
        self.client = AsyncHTTPClient(self.io_loop)
        self.user = User(name='JohnDoe', key=crypto.generate_b64key()).save()
        self.tgs = TGS(name=TGS_NAME, key=TGS_KEY).save()
        self.service = Service(name='chat', key=crypto.generate_b64key()).save()
        self.session_key = crypto.generate_b64key()

    def tearDown(self):
        self.clear_database()
        self.db.drop_database(TEST_DB_URL)

    def get_app(self):
        return make_app()

    @tornado.testing.gen_test
    def test_service_authorization(self):

        request_data = tgs_request_data(self.user, self.tgs, self.service,
                                        session_key=self.session_key)

        request = HTTPRequest(self.get_url('/tgs'), method="POST",
                              headers={'Content-Type': 'application/json'},
                              body=json.dumps(request_data))

        response = yield self.client.fetch(request)
        data = decrypt_json(response.body, self.session_key)
        for key in ['service', 'service_ticket', 'client_service_sk', 'time_to_live']:
            self.assertIn(key, data)

        ticket = decrypt_json(data['service_ticket'], self.service.key)
        for key in ['time_to_live', 'user_name', 'timestamp', 'user_ip', 'service',
                    'client_service_sk']:
            self.assertIn(key, ticket)

        for key in ['client_service_sk', "time_to_live", "service"]:
            self.assertEqual(data[key], ticket[key], "{} don't match".format(key))


if __name__ == '__main__':
    tornado.testing.main()
