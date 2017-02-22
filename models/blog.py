# libraries to import
from google.appengine.ext import db
from models.userinfo import UserInfo


# blog post db
class Blog(db.Model):
    subject = db.StringProperty(required=True)
    body = db.TextProperty(required=True)
    user = db.ReferenceProperty(UserInfo, collection_name='user_posts')
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(required=True)
    liked_by = db.StringListProperty()
