from kerberos import crypto
from kerberos.authservice.models import User
from kerberos.utils import get_timestamp


def as_request_data(user, tgs):
    if isinstance(user, str):
        user = User.objects.get(name=user)
    if isinstance(tgs, str):
        tgs = User.objects.get(name=tgs)

    # prepare AS AS_REQ:
    json_dict = {
        "tgs_name": tgs.name,
        "timestamp": get_timestamp()
    }
    as_req = crypto.encrypt_json(json_dict, user.key)

    return {'login': user.name, 'encrypted': as_req}
