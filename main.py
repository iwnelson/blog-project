#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# python libraries to import

import os
import hashlib
import hmac
import datetime
import jinja2
import webapp2
import random
import re
import string
from google.appengine.ext import db

# jinja2 templates set up

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader
            (template_dir), autoescape = True)

# secret key for hmac'ing user ID's

secret = '''aab39e74ab89d8059645cbd9872bb358d735bc59b654e1c6156d292f3
            0dc610c9fc1ab651d6853310b425f13a76e5d527fd02bcb7ea1ab4ce3
            e16d47dada8a59'''


# encryption functions

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))

def make_pw_hash(username, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(username+pw+salt).hexdigest()
    return '%s|%s' % (h, salt)

def check_pw_hash(username, pw, stored_hash):
    salt = stored_hash.split('|')[1]
    return stored_hash == make_pw_hash(username, pw, salt)

# general handler functions
class Handler(webapp2.RequestHandler):

    # simplifies write
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    # renders html file with jinja substitution
    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    # adds write function to render_str to display page with jinja
    # substution
    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    # sets cookie using hmac encyption for security
    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    # verifies user cookies with hmac function for validity
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    # takes user_id and adds secure hmac cookie for it
    def login(self, user_id): # user_id must be datastore entity
        user_id = str(user_id.key().id())
        self.set_secure_cookie('user_id', user_id)

    # overwrites user_id function with null value
    def logout(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=; Path=/')

# username/password/email validity verification functions

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# blog post db
class Blog(db.Model):
    subject = db.StringProperty(required = True)
    post = db.TextProperty(required = True)
    user_id = db.IntegerProperty(required = True)
    username = db.StringProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    likes = db.IntegerProperty(required = True)
    comments = db.StringListProperty()
    liked_by = db.StringListProperty()

# user db
class UserInfo(db.Model):
    username = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty(required = True)

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
    def register(cls, username, password, email = None):
        pw_hash = make_pw_hash(username, password)
        return UserInfo(username = username,
                        pw_hash = pw_hash,
                        email = email)

    # verifies username + pw, if true, returns user entity
    @classmethod
    def login(cls, username, password):
        user = cls.by_name(username)
        if user:
            if check_pw_hash(username, password, user.pw_hash):
                return user

# blog main page that lists entries
class BlogMain(Handler):
    def get(self):
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
        else:
            user_id = None
        posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY created
                               DESC LIMIT 10''')

        self.render('blog-main.html', posts = posts,
                                      user_id = user_id)

    def post(self):
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
        else:
            user_id = None
        like = self.request.get('like')
        comment = self.request.get('comment')
        delete_comment = self.request.get('delete_comment')
        edit_comment = self.request.get('edit_comment')
        delete_post = self.request.get('delete_post')
        edit_post = self.request.get('edit_post')

        # likes/unlikes post with validity checks
        if like:
            post = Blog.get_by_id(int(like))

            if not user_id:
                error = 'You must log in to like posts.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif int(user_id) == post.user_id:
                error = 'You cannnot like your own post, you egomaniac.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif user_id in post.liked_by:
                post.liked_by.remove(user_id)
                post.likes += -1
                post.put()
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             user_id = user_id)

            elif like and user_id:
                post.likes += 1
                post.liked_by.append(user_id)
                post.put()
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             user_id = user_id)

        # redirects to comment on post with validity checks
        if comment:
            post = Blog.get_by_id(int(comment))

            if not user_id:
                error = 'You must log in to comment on posts.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif comment and user_id:
                self.redirect('/blog/com/?postid=%s' % comment)

        # deletes comments with validity checks
        if delete_comment:
            post = Blog.get_by_id(int(delete_comment.split('|')[-1]))
            comment_user = delete_comment.split('|')[-2]

            if not user_id:
                error = 'You must log in to delete comments.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username != comment_user:
                error = 'You can only delete your own comments.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username == comment_user:
                post.comments.remove(delete_comment)
                post.put()
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             user_id = user_id)

        # redirects to edit comments page with validity checks
        if edit_comment:
            post_id = edit_comment.split('|')[-1]
            post = Blog.get_by_id(int(post_id))
            comment_user = edit_comment.split('|')[-2]

            if not user_id:
                error = 'You must log in to edit comments.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username != comment_user:
                error = 'You can only edit your own comments.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username == comment_user:
                self.redirect('/blog/edit-com/?edit_comment=%s' %
                                                edit_comment)

        # deletes posts with validity checks
        if delete_post:
            post = Blog.get_by_id(int(delete_post))

            if not user_id:
                error = 'You must log in to delete posts.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif post.user_id != int(user_id):
                error = 'You can only delete your own posts.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif post.user_id == int(user_id):
                post.delete()
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             user_id = user_id)

        # redirects to edit posts page with validity checks
        if edit_post:
            post = Blog.get_by_id(int(edit_post))

            if not user_id:
                error = 'You must log in to edit posts.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif post.user_id != int(user_id):
                error = 'You can only edit your own posts.'
                posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY
                                       created DESC LIMIT 10''')
                self.render('blog-main.html', posts = posts,
                             error = error, user_id = user_id)

            elif post.user_id == int(user_id):
                self.redirect('/blog/edit-post/?postid=%s' %
                                            str(post.key().id()))


# new post page
class NewPost(Handler):
    def get(self):
        user_id = self.read_secure_cookie('user_id')
        if not user_id:
            self.redirect('/blog/login')
        else:
            self.render('blog-new-post.html')

    def post(self):
        subject = self.request.get("subject")
        post = self.request.get("post")
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
        else:
            user_id = None
        username = UserInfo.by_id(user_id).username

        if subject and post:
            p = Blog(subject = subject, post = post,
              user_id = int(user_id), username = username, likes = 0)
            p.put()
            self.redirect('/blog/pl/?postid=%s' % str(p.key().id()))
        else:
            error = '''You must provide a Subject and Post to submit
                       your entry, you jabroni.'''
            self.render('blog-new-post.html', subject = subject,
                        post = post, error = error)

# edit post page
class EditPost(Handler):
    def get(self):
        user_id = self.read_secure_cookie('user_id')
        post_id = self.request.get('postid')
        post_to_edit = Blog.get_by_id(int(post_id))
        if not user_id:
            self.redirect('/blog/login')
        else:
            self.render('blog-edit-post.html',
                         subject = post_to_edit.subject,
                         post = post_to_edit.post)

    def post(self):
        user_id = self.read_secure_cookie('user_id')
        post_id = self.request.get('postid')
        post_to_edit = Blog.get_by_id(int(post_id))

        subject = self.request.get("subject")
        post = self.request.get("post")

        if not subject and post:
            error = '''You must provide a Subject and Post to submit
                       your entry, you jabroni.'''
            self.render('blog-edit-post.html', subject = subject,
                        post = post, error = error)
        elif post_to_edit.user_id != int(user_id):
            error = 'You can only edit your own posts'
            self.render('blog-edit-post.html', subject = subject,
                        post = post, error = error)
        elif post_to_edit.user_id == int(user_id):
            post_to_edit.subject = subject
            post_to_edit.post = post
            post_to_edit.put()
            self.redirect('/blog/pl/?postid=%s' %
                            str(post_to_edit.key().id()))

# permalink page
class Permalink(Handler):
    def get(self):
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
        else:
            user_id = None
        key = self.request.get('postid')
        if key:
            post = Blog.get_by_id(int(key))


        if not post:
            self.error(404)
            return

        self.render('blog-permalink.html', post = post,
                     user_id = user_id)

    def post(self):
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
        else:
            user_id = None
        key = self.request.get('postid')
        like = self.request.get('like')
        comment = self.request.get('comment')
        edit_comment = self.request.get('edit_comment')
        delete_comment = self.request.get('delete_comment')
        delete_post = self.request.get('delete_post')
        edit_post = self.request.get('edit_post')

        # likes/unlikes post with validity checks
        if key:
            post = Blog.get_by_id(int(key))

        if like:
            if not user_id:
                error = 'You must log in to like posts.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif int(user_id) == post.user_id:
                error = 'You cannnot like your own post, you egomaniac.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif user_id in post.liked_by:
                post.liked_by.remove(user_id)
                post.likes += -1
                post.put()
                self.render('blog-permalink.html', post = post,
                             user_id = user_id)

            elif like and user_id:
                post.likes += 1
                post.liked_by.append(user_id)
                post.put()
                self.render('blog-permalink.html', post = post,
                             user_id = user_id)

        # redirects to comment page with validity checks
        if comment:
            if not user_id:
                error = 'You must log in to comment on posts.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif comment and user_id:
                self.redirect('/blog/com/?postid=%s' % comment)

        # redirects to edit comment page with validity checks
        if edit_comment:
            comment_user = edit_comment.split('|')[-2]

            if not user_id:
                error = 'You must log in to edit comments.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username != comment_user:
                error = 'You can only edit your own comments.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username == comment_user:
                self.redirect('/blog/edit-com/?edit_comment=%s' %
                                                    edit_comment)

        # deletes comments with validity checks
        if delete_comment:
            comment_user = delete_comment.split('|')[-2]

            if not user_id:
                error = 'You must log in to delete comments.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username != comment_user:
                error = 'You can only delete your own comments.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username == comment_user:
                post.comments.remove(delete_comment)
                post.put()
                self.render('blog-permalink.html', post = post,
                             user_id = user_id)

        # deletes posts with validity checks
        if delete_post:
            if not user_id:
                error = 'You must log in to delete posts.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif post.user_id != int(user_id):
                error = 'You can only delete your own posts.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif post.user_id == int(user_id):
                post.delete()
                self.redirect('/blog')

        # redirects to edit post page with validity checks
        if edit_post:
            if not user_id:
                error = 'You must log in to edit posts.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif post.user_id != int(user_id):
                error = 'You can only edit your own posts.'
                self.render('blog-permalink.html', post = post,
                             error = error, user_id = user_id)

            elif post.user_id == int(user_id):
                self.redirect('/blog/edit-post/?postid=%s' %
                                            str(post.key().id()))

# comment page
class Comment(Handler):
    def get(self):
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
        else:
            user_id = None
        key = self.request.get('postid')
        if key:
            post = Blog.get_by_id(int(key))


        if not key:
            self.error(404)
            return

        self.render('blog-comment-page.html', post = post,
                     comment = '', user_id = user_id)

    def post(self):
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
        else:
            user_id = None
        key = self.request.get('postid')
        like = self.request.get('like')
        comment = self.request.get('comment')
        edit_comment = self.request.get('edit_comment')
        delete_comment = self.request.get('delete_comment')
        delete_post = self.request.get('delete_post')
        edit_post = self.request.get('edit_post')

        if key:
            post = Blog.get_by_id(int(key))

        # likes/unlikes post with validity checks
        if like:
            if not user_id:
                error = 'You must log in to like posts.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif int(user_id) == post.user_id:
                error = "You can't like your own post, ya egomaniac."
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif user_id in post.liked_by:
                post.liked_by.remove(user_id)
                post.likes += -1
                post.put()
                self.render('blog-comment-page.html', post = post,
                             user_id = user_id)

            elif like and user_id:
                post.likes += 1
                post.liked_by.append(user_id)
                post.put()
                self.render('blog-comment-page.html', post = post,
                             user_id = user_id)

        # comments on post with validity checks
        if comment:
            if not user_id:
                error = 'You must log in to comment on posts.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif comment and user_id:
                commenting_user = UserInfo.by_id(user_id)
                post.comments.append(comment + '|' +
                                commenting_user.username + '|' + key)
                post.put()
                self.render('blog-comment-page.html', post = post,
                             user_id = user_id)

        # redirects to edit comments page with validity checks
        if edit_comment:
            comment_user = edit_comment.split('|')[-2]

            if not user_id:
                error = 'You must log in to edit comments.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username != comment_user:
                error = 'You can only edit your own comments.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username == comment_user:
                self.redirect('/blog/edit-com/?edit_comment=%s' %
                                                    edit_comment)

        # deletes comments with validity checks
        if delete_comment:
            comment_user = delete_comment.split('|')[-2]

            if not user_id:
                error = 'You must log in to delete comments.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username != comment_user:
                error = 'You can only delete your own comments.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif UserInfo.by_id(user_id).username == comment_user:
                post.comments.remove(delete_comment)
                post.put()
                self.render('blog-comment-page.html', post = post,
                             user_id = user_id)

        # deletes posts with validity checks
        if delete_post:
            if not user_id:
                error = 'You must log in to delete posts.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif post.user_id != int(user_id):
                error = 'You can only delete your own posts.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif post.user_id == int(user_id):
                post.delete()
                self.redirect('/blog')

        # redirects to edit post page with validity checks
        if edit_post:
            if not user_id:
                error = 'You must log in to edit posts.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif post.user_id != int(user_id):
                error = 'You can only edit your own posts.'
                self.render('blog-comment-page.html', post = post,
                             error = error, user_id = user_id)

            elif post.user_id == int(user_id):
                self.redirect('/blog/edit-post/?postid=%s' %
                                        str(post.key().id()))

# edit comments
class EditComment(Handler):
    def get(self):
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
        else:
            user_id = None
        edit_comment = self.request.get('edit_comment')
        comment_text = edit_comment.split('|')[0]
        key = edit_comment.split('|')[-1]
        if key:
            post = Blog.get_by_id(int(key))


        if not key:
            self.error(404)
            return

        self.render('blog-edit-comment.html', post = post,
                     comment = comment_text, user_id = user_id)

    def post(self):
        edit_comment = self.request.get('edit_comment')
        comment_text = edit_comment.split('|')[0]
        key = edit_comment.split('|')[-1]
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
        else:
            user_id = None
        like = self.request.get('like')
        comment = self.request.get('comment')
        comment_change = self.request.get('comment_change')
        delete_comment = self.request.get('delete_comment')
        edit_diff_comment = self.request.get('edit_comment')
        delete_post = self.request.get('delete_post')
        edit_post = self.request.get('edit_post')

        if key:
            post = Blog.get_by_id(int(key))

        # likes/unlikes post with validity checks
        if like:
            if not user_id:
                error = 'You must log in to like posts.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif int(user_id) == post.user_id:
                error = "You can't like your own post, ya egomaniac."
                self.render('blog-cedit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif user_id in post.liked_by:
                post.liked_by.remove(user_id)
                post.likes += -1
                post.put()
                self.render('blog-edit-comment.html', post = post,
                        comment = comment_text, user_id = user_id)

            elif like and user_id:
                post.likes += 1
                post.liked_by.append(user_id)
                post.put()
                self.render('blog-edit-comment.html', post = post,
                        comment = comment_text, user_id = user_id)

        # redirects to comment on posts page with validity checks
        if comment:
            if not user_id:
                error = 'You must log in to comment on posts.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif comment and user_id:
                self.redirect('/blog/com/?postid=%s' % comment)

        # edits comments with validity checks
        if comment_change:
            exist_comm_user = edit_comment.split('|')[-2]

            if not user_id:
                error = 'You must log in to edit comments.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif UserInfo.by_id(user_id).username != exist_comm_user:
                error = 'You can only edit your own comments.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif UserInfo.by_id(user_id).username == exist_comm_user:
                comment_index = post.comments.index(edit_comment)
                commenting_user = UserInfo.by_id(user_id)
                username = commenting_user.username
                new_com = comment_change + '|' + username + '|' + key
                post.comments[comment_index] = new_com
                post.put()
                self.redirect('/blog/pl/?postid=%s' % key)

        # redirects to a page to edit a different comment with
        # validity checks
        if edit_diff_comment:
            comment_user = edit_diff_comment.split('|')[-2]

            if not user_id:
                error = 'You must log in to edit comments.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif UserInfo.by_id(user_id).username != comment_user:
                error = 'You can only edit your own comments.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif UserInfo.by_id(user_id).username == comment_user:
                self.render('blog-edit-comment.html', post = post,
                        comment = comment_text, user_id = user_id)


        # deletes comments with validity checks
        if delete_comment:
            comment_user = delete_comment.split('|')[-2]

            if not user_id:
                error = 'You must log in to delete comments.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif UserInfo.by_id(user_id).username != comment_user:
                error = 'You can only delete your own comments.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif UserInfo.by_id(user_id).username == comment_user:
                post.comments.remove(delete_comment)
                post.put()
                self.render('blog-edit-comment.html', post = post,
                        comment = comment_text, user_id = user_id)

        # deletes posts with validity checks
        if delete_post:
            if not user_id:
                error = 'You must log in to delete posts.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif post.user_id != int(user_id):
                error = 'You can only delete your own posts.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif post.user_id == int(user_id):
                post.delete()
                self.redirect('/blog')

        # redirects to edit posts page with validity checks
        if edit_post:
            if not user_id:
                error = 'You must log in to edit posts.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif post.user_id != int(user_id):
                error = 'You can only edit your own posts.'
                self.render('blog-edit-comment.html', post = post,
                             comment = comment_text, error = error,
                             user_id = user_id)

            elif post.user_id == int(user_id):
                self.redirect('/blog/edit-post/?postid=%s' %
                                            str(post.key().id()))


# creates user entity
class UserSignup(Handler):
    def get(self):
        user_id = self.read_secure_cookie('user_id')
        if user_id:
            self.redirect('/blog/welcome-page')
        else:
            self.render('blog-user-signup-page.html')

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        confirm = self.request.get('confirm')
        email = self.request.get('email')

        params = {'username' : username, 'email' : email}

        # validity checks for valid sign up information
        if not valid_username(username):
            params['error_inval_username'] = '''Please enter a valid
                                        username, you little minx'''
            have_error = True

        if UserInfo.by_name(username):
            params['error_unavail_username'] = '''This is hard for me
                                        to say to you, but that
                                        username is taken'''
            have_error = True

        if not valid_password(password):
            params['error_password'] = '''DANGER! PASSWORD DOES NOT
                                        COMPUTE! BLEEP BLORP!'''
            have_error = True
        elif password != confirm:
            params['error_confirm'] = '''Stop it with these mis-matchy
                                       passwords ya jive turkey'''
            have_error = True

        if not valid_email(email):
            params['error_inval_email'] = '''UGHHHH we've been over
                                             this!'''
            have_error = True

        if UserInfo.by_email(email):
            params['error_unavail_email'] = '''ZOINKS! We already
                            have that email registered'''
            have_error = True


        if have_error:
            self.render('blog-user-signup-page.html', **params)
        else:
            u = UserInfo(username = username, pw_hash = make_pw_hash(
                username, password), email = email)
            u.put()
            user_id = str(u.key().id())
            self.set_secure_cookie('user_id', user_id)
            self.redirect('/blog/welcome-page')

# landing page after successful signup/login
class WelcomePage(Handler):
    def get(self):
        user_id = self.read_secure_cookie('user_id')
        if not user_id:
            self.redirect('/blog/login')
        else:
            user = UserInfo.get_by_id(int(user_id.split('|')[0]))
            username = user.username
            self.render('blog-welcome-page.html',
                         username = username)

# login page
class Login(Handler):
    def get(self, username = ''):
        user_id = self.read_secure_cookie('user_id')
        if user_id:
            self.redirect('/blog/welcome-page')
        else:
            self.render('blog-login.html', username = username)

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')

        user = UserInfo.login(username, password)

        if not username and valid_password(password):
            error = 'You must enter your username and password.'
            have_error = True
        elif not user:
            error = 'Not valid username and password combination.'
            have_error = True

        if have_error:
            self.render('blog-login.html', username = username,
                         error = error)
        else:
            self.login(user)
            self.redirect('/blog/welcome-page')

# logout page
class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog/login')




app = webapp2.WSGIApplication([('/blog', BlogMain),
                               ('/blog/signup', UserSignup),
                               ('/blog/welcome-page', WelcomePage),
                               ('/blog/new-post', NewPost),
                               ('/blog/edit-post/', EditPost),
                               ('/blog/com/', Comment),
                               ('/blog/edit-com/', EditComment),
                               ('/blog/pl/', Permalink),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout)
                              ],
                              debug=True)





