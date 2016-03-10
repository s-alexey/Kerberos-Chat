#!/usr/bin/env python

from distutils.core import setup

setup_args = {
      'name': 'KerberosChat',
      'version': '0.0',
      'description': 'Simple chat with Kerberos authentication',
      'author': 'Alexey Suharevich',
      'author_email': 'alexey.suharevich@yandex.by',
      'url': 'https://github.com/s-alexey/Kerberos-Chat',
      'packages': ['kerberos', 'kerberos.authservice', 'kerberos.tgs', 'kerberos.chat'],
      'install_requires': [
          'tornado',
          'pycrypto',
          'mongoengine',
      ],
}

setup(**setup_args)
