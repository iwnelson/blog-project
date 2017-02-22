# libraries to import
from google.appengine.ext import db
from models.userinfo import UserInfo
from models.blog import Blog


# blog post db
class Comments(db.Model):
    user = db.ReferenceProperty(UserInfo, collection_name='user_comments')
    post = db.ReferenceProperty(Blog, collection_name='post_comments')
    text = db.TextProperty(required=True)
    timestamp = db.DateTimeProperty(auto_now_add=True)
