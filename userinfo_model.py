# libraries to import
from google.appengine.ext import db
from security import make_pw_hash, check_pw_hash


# user db
class UserInfo(db.Model):
    username = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty(required=True)

# classmethod functions for class UserInfo

    # looks up user entity by id number
    @classmethod
    def by_id(cls, u_id):
        return UserInfo.get_by_id(int(u_id))

    # looks up user entity by username
    @classmethod
    def by_name(cls, name):
        return UserInfo.all().filter('username =', name).get()

    # looks up user entity by email
    @classmethod
    def by_email(cls, email):
        return UserInfo.all().filter('email =', email).get()

    # creates user entity but DOES NOT store
    @classmethod
    def register(cls, username, password, email):
        pw_hash = make_pw_hash(username, password)
        return UserInfo(username=username,
                        pw_hash=pw_hash,
                        email=email)

    # verifies username + pw, if true, returns user entity
    @classmethod
    def login(cls, username, password):
        user = cls.by_name(username)
        if user:
            if check_pw_hash(username, password, user.pw_hash):
                return user
