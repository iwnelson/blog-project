# libraries to import
from google.appengine.ext import db


# blog post db
class Blog(db.Model):
    subject = db.StringProperty(required=True)
    post = db.TextProperty(required=True)
    user_id = db.IntegerProperty(required=True)
    username = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    likes = db.IntegerProperty(required=True)
    comments = db.StringListProperty()
    liked_by = db.StringListProperty()
