from kerberos import crypto
from kerberos.authservice.models import User, TGS
from kerberos.tgs.models import Service
from kerberos.utils import get_timestamp, TIME_TO_LIVE_TGS_TICKET, TIME_TO_LIVE_SESSION_KEY


def as_request_data(user, tgs):
    if isinstance(user, str):
        user = User.objects.get(name=user)
    if isinstance(tgs, str):
        tgs = TGS.objects.get(name=tgs)

    # prepare AS AS_REQ:
    json_dict = {
        "tgs_name": tgs.name,
        "timestamp": get_timestamp()
    }
    as_req = crypto.encrypt_json(json_dict, user.key)

    return {'login': user.name, 'encrypted': as_req}


def tgs_request_data(user, tgs, service, session_key=None, ip='127.0.0.1'):
    if isinstance(user, str):
        user = User.objects.get(name=user)
    if isinstance(tgs, str):
        tgs = TGS.objects.get(name=tgs)
    if isinstance(service, str):
        service = Service.get(name=service)

    if session_key is None:
        session_key = crypto.generate_b64key()

    ticket = {
        "session_key": session_key,
        "user_name": user.name,
        "user_ip": ip,
        "tgs_name": tgs.name,
        "tgs_ticket_time_to_live": TIME_TO_LIVE_TGS_TICKET,
        "session_key_time_to_live": TIME_TO_LIVE_SESSION_KEY,
        "timestamp": get_timestamp()
    }
    ticket = crypto.encrypt_json(ticket, tgs.key)

    authenticator = {
        "user_name": user.name,
        "timestamp": get_timestamp()
    }
    authenticator = crypto.encrypt_json(authenticator, session_key)

    return {
        'tgs_ticket': ticket,
        'authenticator': authenticator,
        'service': service.name,
    }
