# python standard libraries to import
import hashlib
import hmac
import random
import string

# other modules to import
from modules.hmac_secret import secret


# encryption functions
def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())


def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val


def make_salt():
    return ''.join(random.choice(string.letters) for i in range(5))


def make_pw_hash(username, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username+pw+salt).hexdigest()
    return '%s|%s' % (h, salt)


def check_pw_hash(username, pw, stored_hash):
    salt = stored_hash.split('|')[1]
    return stored_hash == make_pw_hash(username, pw, salt)
