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

# python standard libraries to import
import os
import jinja2
import webapp2
import re

# other python libraries to import
from google.appengine.ext import db
from models.userinfo import UserInfo
from models.blog import Blog
from models.comments import Comments
from modules.security import make_secure_val, check_secure_val

# jinja2 templates set up
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader
                               (template_dir), autoescape=True)


# Handlers
class MainHandler(webapp2.RequestHandler):
    """General functions and functions that retrieve/set variables from
    cookies/url for blog"""
    def write(self, *a, **kw):
        '''Simplifies write'''
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        '''Renders html file with jinja substitution'''
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        '''Adds write function to render_str to display page with jinja
        substution'''
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, val):
        '''Sets cookie using hmac encyption for security'''
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie', '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        '''Verifies user cookies with hmac function for validity'''
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        '''Takes user_id(must exist in UserInfo) and adds secure hmac cookie
        for it'''
        user_id = str(user.key().id())
        self.set_secure_cookie('user_id', user_id)

    def logout(self):
        '''Overwrites user_id function with None value'''
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def get_user(self):
        '''Retrieves user id from cookie, checks hmac encryption if user id exists
        in UserInfo database. If user_id exists, returns user_id and user
        entity. If not, returns None for both'''
        user_id_cookie = self.read_secure_cookie('user_id')
        if user_id_cookie:
            user_id = user_id_cookie.split('|')[0]
            user = UserInfo.by_id(int(user_id))
            if not user:
                user_id = None
                user = None
        else:
            user_id = None
            user = None
        return user_id, user


class ValidityChecksHandler():
    """Checks validity of signup parameters, ie. username, password, email"""
    def valid_username(self, username):
        USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
        return username and USER_RE.match(username)

    def valid_password(self, password):
        PASS_RE = re.compile(r"^.{3,20}$")
        return password and PASS_RE.match(password)

    def valid_email(self, email):
        EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
        return not email or EMAIL_RE.match(email)


class PostsHandler():
    """Functions for new posts and editing posts"""
    def get_post(self, post_id):
        '''Retrieves post id from url. If post id matches post in Blog
        database, returns post, if not, returns None'''
        if post_id:
            post = Blog.get_by_id(int(post_id))
        if post:
            return post

    def new_post(self, subject, body, user):
        '''Creates a new post and stores to Blog database'''
        post = Blog(subject=subject, body=body, user=user, likes=0)
        post.put()
        redirect = '/blog/pl/%s' % str(post.key().id())
        return redirect

    def user_owns_post(self, post, user):
        if post.user.key() == user.key():
            return True
        else:
            return False

    def edit_post(self, post, new_subject, new_body):
        '''Edits exising post & subject and stores new vals to Blog Database'''
        post.subject = new_subject
        post.body = new_body
        post.put()
        redirect = '/blog/pl/%s' % str(post.key().id())
        return redirect

    def delete_post(self, post):
        for comment in post.post_comments:
            comment.delete()
        post.delete()
        redirect = '/blog'
        return redirect


class LikesHandler():
    """Contains function to like/unlike post & store data to Blog database
    including permission check"""
    def like(self, post, user_id):
        if user_id in post.liked_by:
            post.liked_by.remove(user_id)
            post.likes += -1
            post.put()
        elif user_id not in post.liked_by:
            post.likes += 1
            post.liked_by.append(user_id)
            post.put()
        redirect = '/blog/pl/%s' % str(post.key().id())
        return redirect


class CommentsHandler():
    """Contains functions to add, edit, and delete comments"""
    def get_comment(self, comment_id):
        '''Retrieves comment id from url. If comment id matches comment in Comments
        database, returns comment, if not, returns None'''
        if comment_id:
            comment = Comments.get_by_id(int(comment_id))
        if comment:
            return comment

    def add_comment(self, post, user, comment_text):
        '''Adds comment'''
        comment = Comments(user=user, post=post, text=comment_text)
        comment.put()
        redirect = '/blog/pl/%s' % str(post.key().id())
        return redirect

    def user_owns_comment(self, comment, user):
        if comment.user.key() == user.key():
            return True
        else:
            return False

    def edit_comment(self, comment, new_comment_text):
        '''Edits exising post & subject and stores new vals to Blog Database'''
        comment.text = new_comment_text
        comment.put()
        redirect = '/blog/pl/%s' % str(comment.post.key().id())
        return redirect

    def delete_comment(self, comment):
        post = self.get_post(comment.post.key().id())
        if post:
            redirect = '/blog/pl/%s' % str(post.key().id())
        else:
            redirect = '/blog'
        comment.delete()
        return redirect


class BlogMain(MainHandler, PostsHandler):
    '''Blog main page that lists 10 most recent entries and redirects to action
    pages'''
    def get(self):
        user_id, user = self.get_user()
        posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY created
                               DESC LIMIT 10''')
        template = 'blog-main.html'
        params = {'posts': posts, 'user': user}

        self.render(template, **params)


class NewPost(MainHandler, PostsHandler):
    '''New post page'''
    def get(self):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            self.render('blog-post-page.html', user=user, subject='', body='')

    def post(self):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            subject = self.request.get("subject")
            body = self.request.get("body")
            if subject and body:
                redirect = self.new_post(subject, body, user)
                self.redirect(redirect)
            else:
                error = 'You must provide a Subject and Post'
                self.render('blog-post-page.html', user=user, subject=subject,
                            body=body, error=error)


class EditPost(MainHandler, PostsHandler):
    '''Edit existing post page'''
    def get(self, post_id):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            post = self.get_post(post_id)
            if not post:
                self.redirect('/blog')
            else:
                if self.user_owns_post(post, user):
                    self.render('blog-post-page.html', user=user,
                                subject=post.subject, body=post.body)
                else:
                    error = 'You can only edit your own posts'
                    self.render('blog-permalink.html', user=user,
                                error=error, post=post)

    def post(self, post_id):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            post = self.get_post(post_id)
            if not post:
                self.redirect('/blog')
            else:
                if self.user_owns_post(post, user):
                    new_subject = self.request.get('subject')
                    new_body = self.request.get('body')
                    if new_subject and new_body:
                        redirect = self.edit_post(post, new_subject,
                                                  new_body)
                        self.redirect(redirect)
                    else:
                        error = 'You must provide a Subject and Post'
                        self.render('blog-post-page.html', user=user,
                                    subject=post.subject, body=post.body,
                                    error=error)
                else:
                    error = 'You can only edit your own posts'
                    self.render('blog-permalink.html', user=user,
                                error=error, post=post)


class DeletePost(MainHandler, PostsHandler):
    """Deletes posts with permission checks"""
    def get(self, post_id):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            post = self.get_post(post_id)
            if not post:
                self.redirect('/blog')
            else:
                if self.user_owns_post(post, user):
                    redirect = self.delete_post(post)
                    self.redirect(redirect)
                else:
                    error = 'You can only delete your own posts'
                    self.render('blog-permalink.html', user=user,
                                error=error, post=post)


class Permalink(MainHandler, PostsHandler):
    '''Permalink page - page that renders single post and comments.'''
    def get(self, post_id):
        user_id, user = self.get_user()
        post = self.get_post(post_id)
        if not post:
            self.redirect('/blog')
        else:
            self.render('blog-permalink.html', user=user, post=post)


class Comment(MainHandler, PostsHandler, CommentsHandler):
    '''Posts new comments on blog posts.'''
    def get(self, post_id):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            post = self.get_post(post_id)
            if not post:
                self.redirect('/blog')
            else:
                self.render('blog-comment-page.html', user=user, post=post,
                            comment='')

    def post(self, post_id):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            post = self.get_post(post_id)
            if not post:
                self.redirect('/blog')
            else:
                comment_text = self.request.get('comment_text')
                if comment_text:
                    redirect = self.add_comment(post, user, comment_text)
                    self.redirect(redirect)
                else:
                    error = "You can't post a blank comment"
                    self.render('blog-comment-page.html', user=user, post=post,
                                comment='', error=error)


class EditComment(MainHandler, PostsHandler, CommentsHandler):
    '''Page to edit existing comments'''
    def get(self, comment_id):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            comment = self.get_comment(comment_id)
            if not comment:
                self.redirect('/blog')
            else:
                post = self.get_post(comment.post.key().id())
                if not post:
                    self.redirect('/blog')
                else:
                    if self.user_owns_comment(comment, user):
                        self.render('blog-comment-page.html', user=user,
                                    post=post, comment_text=comment.text)
                    else:
                        error = 'You can only edit your own comments'
                        self.render('blog-permalink.html', user=user,
                                    error=error, post=post)

    def post(self, comment_id):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            comment = self.get_comment(comment_id)
            if not comment:
                self.redirect('/blog')
            else:
                post = self.get_post(comment.post.key().id())
                if not post:
                    self.redirect('/blog')
                else:
                    if self.user_owns_comment(comment, user):
                        new_comment_text = self.request.get('comment_text')
                        if new_comment_text:
                            redirect = self.edit_comment(comment,
                                                         new_comment_text)
                            self.redirect(redirect)
                        else:
                            error = "You can't post a blank comment"
                            self.render('blog-comment-page.html', user=user,
                                        post=post, comment=comment.text,
                                        error=error)
                    else:
                        error = 'You can only edit your own comments'
                        self.render('blog-permalink.html', user=user,
                                    error=error, post=post)


class DeleteComment(MainHandler, PostsHandler, CommentsHandler):
    """Deletes comments with permission checks"""
    def get(self, comment_id):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            comment = self.get_comment(comment_id)
            if not comment:
                self.redirect('/blog')
            else:
                if self.user_owns_comment(comment, user):
                    redirect = self.delete_comment(comment)
                    self.redirect(redirect)
                else:
                    post = self.get_post(comment.post.key().id())
                    if post:
                        error = 'You can only delete your own comments'
                        self.render('blog-permalink.html', user=user,
                                    error=error, post=post)
                    else:
                        self.redirect('/blog')


class LikePost(MainHandler, PostsHandler, LikesHandler):
    """Processes post like."""
    def get(self, post_id):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            post = self.get_post(post_id)
            if not post:
                self.redirect('/blog')
            else:
                if self.user_owns_post(post, user):
                    error = "You can't like your own post"
                    self.render('blog-permalink.html', user=user,
                                error=error, post=post)
                else:
                    redirect = self.like(post, user_id)
                    self.redirect(redirect)


class UserSignup(MainHandler, ValidityChecksHandler):
    '''Creates and stores new user entity in UserInfo database'''
    def get(self):
        user_id, user = self.get_user()
        template = 'blog-user-signup-page.html'
        if user:
            self.redirect('/blog/welcome-page')
        else:
            self.render(template)

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        confirm = self.request.get('confirm')
        email = self.request.get('email')
        template = 'blog-user-signup-page.html'
        params = {'username': username, 'email': email}

        # validity checks for valid sign up information
        if not self.valid_username(username):
            params['error_inval_username'] = '''Please enter a valid username,
                                                you little minx'''
            have_error = True

        if UserInfo.by_name(username):
            params['error_unavail_username'] = '''This is hard for me to say to
                                                  you, but that username is
                                                  taken'''
            have_error = True

        if not self.valid_password(password):
            params['error_password'] = '''DANGER! PASSWORD DOES NOT COMPUTE!
                                          BLEEP BLORP!'''
            have_error = True
        elif password != confirm:
            params['error_confirm'] = '''Stop it with these mis-matchy
                                         passwords ya jive turkey'''
            have_error = True

        if not self.valid_email(email):
            params['error_inval_email'] = '''UGHHHH we've been over this!'''
            have_error = True

        if UserInfo.by_email(email):
            params['error_unavail_email'] = '''ZOINKS! We already have that
                                               email registered'''
            have_error = True

        if have_error:
            self.render(template, **params)
        else:
            u = UserInfo.register(username, password, email)
            u.put()
            self.login(u)
            self.redirect('/blog/welcome-page')


class WelcomePage(MainHandler):
    '''Landing page after successful signup/login'''
    def get(self):
        user_id, user = self.get_user()
        if not user:
            self.redirect('/blog/login')
        else:
            template = 'blog-welcome-page.html'
            params = {'user': user}
            self.render(template, **params)


class Login(MainHandler):
    '''Log in page'''
    def get(self):
        user_id, user = self.get_user()
        template = 'blog-login.html'
        params = {'username': '', 'password': ''}
        if user:
            self.redirect('/blog/welcome-page')
        else:
            self.render(template, **params)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        template = 'blog-login.html'
        params = {'username': username, 'password': ''}
        user = UserInfo.login(username, password)

        if not user:
            params['error'] = 'Not valid username and password combination.'
            self.render(template, **params)
        else:
            self.login(user)
            self.redirect('/blog/welcome-page')


class Logout(MainHandler):
    '''Logout page'''
    def get(self):
        self.logout()
        self.redirect('/blog/login')


app = webapp2.WSGIApplication([('/blog', BlogMain),
                               ('/blog/signup', UserSignup),
                               ('/blog/welcome-page', WelcomePage),
                               ('/blog/new-post', NewPost),
                               ('/blog/edit-post/([0-9]+)', EditPost),
                               ('/blog/delete-post/([0-9]+)', DeletePost),
                               ('/blog/com/([0-9]+)', Comment),
                               ('/blog/edit-com/([0-9]+)', EditComment),
                               ('/blog/delete-com/([0-9]+)', DeleteComment),
                               ('/blog/like/([0-9]+)', LikePost),
                               ('/blog/pl/([0-9]+)', Permalink),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout)
                               ],
                              debug=True)
