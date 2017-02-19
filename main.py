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
from userinfo_model import UserInfo
from blog_model import Blog
from security import make_secure_val, check_secure_val

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

    def get_post(self):
        '''Retrieves post id from url. If post id matches post in Blog
        database, returns post, if not, returns None'''
        key = self.request.get('postid')
        if key:
            post = Blog.get_by_id(int(key))
        if not post:
            post = None
        return post

    def get_blog_actions(self):
        '''For post actions such as: liking (and unliking), commenting
        (including editing and deleting comments), and deleting posts, pulls
        variables from forms, and returns None values if they do not
        exist'''
        like = self.request.get('like')
        if not like:
            like = None
        comment = self.request.get('comment')
        if not comment:
            comment = None
        delete_comment = self.request.get('delete_comment')
        if not delete_comment:
            delete_comment = None
        edit_comment = self.request.get('edit_comment')
        if not edit_comment:
            edit_comment = None
        delete_post = self.request.get('delete_post')
        if not delete_post:
            delete_post = None
        edit_post = self.request.get('edit_post')
        if not edit_post:
            edit_post = None
        return (like, comment, delete_comment, edit_comment, delete_post,
                edit_post)


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
    def new_post(self, subject, post, user):
        '''Creates a new post and stores to Blog database'''
        username = user.username
        user_id = int(user.key().id())
        p = Blog(subject=subject, post=post, user_id=user_id,
                 username=username, likes=0)
        p.put()
        redirect = '/blog/pl/?postid=%s' % str(p.key().id())
        return redirect

    def edit_post_redirect(self, edit_post, user_id):
        post = Blog.get_by_id(int(edit_post))
        error = None
        redirect = None
        if post.user_id != int(user_id):
            error = 'You can only edit your own posts.'
        else:
            redirect = '/blog/edit-post/?postid=%s' % str(post.key().id())
        return redirect, error

    def edit_post_store(self, post, user_id, new_subject, new_post):
        '''Edits exising post & subject and stores new vals to Blog Database;
        includes permission check'''
        error = None
        redirect = None
        if post.user_id != int(user_id):
            error = 'You can only edit your own posts'
        else:
            post.subject = new_subject
            post.post = new_post
            post.put()
            redirect = '/blog/pl/?postid=%s' % str(post.key().id())
        return redirect, error

    def delete_post(self, delete_post, user_id):
        post = Blog.get_by_id(int(delete_post))
        error = None
        redirect = None
        if post.user_id != int(user_id):
            error = 'You can only delete your own posts.'
        else:
            post.delete()
            redirect = '/blog'
        return redirect, error


class LikesHandler():
    """Contains function to like/unlike post & store data to Blog database
    including permission check"""
    def like(self, like, user_id):
        post = Blog.get_by_id(int(like))
        error = None
        if int(user_id) == post.user_id:
            error = 'You cannnot like your own post, you egomaniac.'
        elif user_id in post.liked_by:
            post.liked_by.remove(user_id)
            post.likes += -1
            post.put()
        elif user_id not in post.liked_by:
            post.likes += 1
            post.liked_by.append(user_id)
            post.put()
        return error


class CommentsHandler():
    """Contains functions to add, edit, and delete comments"""
    def add_comm(self, post, user, comment):
        '''Adds comment'''
        username = user.username
        post_id_str = str(post.key().id())
        post.comments.append(comment + '|' + username + '|' + post_id_str)
        post.put()
        redirect = '/blog/pl/?postid=%s' % post_id_str
        return redirect

    def delete_comm(self, user, comment):
        '''Checks user permission then deletes comment'''
        post_id = comment.split('|')[-1]
        post = Blog.get_by_id(int(post_id))
        comment_user = comment.split('|')[-2]
        username = user.username
        error = None
        if username != comment_user:
            error = 'You can only delete your own comments.'
        else:
            post.comments.remove(comment)
            post.put()
        return error

    def edit_comm_redirect(self, user, edit_comment):
        comment_user = edit_comment.split('|')[-2]
        error = None
        redirect = None
        if user.username != comment_user:
            error = 'You can only edit your own comments'
        else:
            redirect = '/blog/edit-com/?exist_comment=%s' % edit_comment
        return redirect, error

    def edit_comm_post(self, user, exist_comment, comment_change):
        '''Checks user permission then edits comment'''
        post_id = exist_comment.split('|')[-1]
        post = Blog.get_by_id(int(post_id))
        exist_comment_user = exist_comment.split('|')[-2]
        username = user.username
        error = None
        redirect = None
        if username != exist_comment_user:
            error = 'You can only edit your own comments.'
        else:
            comment_index = post.comments.index(exist_comment)
            new_comment = comment_change + '|' + username + '|' + post_id
            post.comments[comment_index] = new_comment
            post.put()
            redirect = '/blog/pl/?postid=%s' % post_id
        return redirect, error


class BlogMain(MainHandler, PostsHandler, LikesHandler, CommentsHandler):
    '''Blog main page that lists 10 most recent entries and allows actions on
    posts'''
    def get(self):
        user_id, user = self.get_user()
        posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY created
                               DESC LIMIT 10''')
        template = 'blog-main.html'
        params = {'posts': posts, 'user': user}

        self.render(template, **params)

    def post(self):
        user_id, user = self.get_user()
        (like, comment, delete_comment, edit_comment, delete_post,
            edit_post) = self.get_blog_actions()
        template = 'blog-main.html'
        params = {'user': user}
        error = None
        redirect = None

        if not user:
            error = 'You must log in to act on posts'
        else:
            if like:
                error = self.like(like, user_id)

            elif comment:
                redirect = '/blog/com/?postid=%s' % comment

            elif delete_comment:
                error = self.delete_comm(user, delete_comment)

            elif edit_comment:
                redirect, error = self.edit_comm_redirect(user, edit_comment)

            elif delete_post:
                redirect, error = self.delete_post(delete_post, user_id)

            elif edit_post:
                redirect, error = self.edit_post_redirect(edit_post, user_id)

        if error:
            params['error'] = error

        if not redirect:
            posts = db.GqlQuery('''SELECT * FROM Blog ORDER BY created
                                   DESC LIMIT 10''')
            params['posts'] = posts
            self.render(template, **params)
        else:
            self.redirect(redirect)


class NewPost(MainHandler, PostsHandler):
    '''New post page'''
    def get(self):
        user_id, user = self.get_user()
        template = 'blog-post-page.html'
        params = {'user': user, 'subject': '', 'post': ''}

        if not user:
            self.redirect('/blog/login')
        else:
            self.render(template, **params)

    def post(self):
        user_id, user = self.get_user()
        template = 'blog-post-page.html'
        subject = self.request.get("subject")
        post = self.request.get("post")
        params = {'user': user, 'subject': subject, 'post': post}
        redirect = None

        if not user:
            self.redirect('/blog/login')
        elif subject and post:
            redirect = self.new_post(subject, post, user)
        else:
            params['error'] = 'You must provide a Subject and Post'

        if redirect:
            self.redirect(redirect)
        else:
            self.render(template, **params)


class EditPost(MainHandler, PostsHandler):
    '''Edit existing post page'''
    def get(self):
        user_id, user = self.get_user()
        post = self.get_post()
        template = 'blog-post-page.html'
        params = {'user': user, 'subject': post.subject, 'post': post.post}

        if not user:
            self.redirect('/blog/login')
        else:
            self.render(template, **params)

    def post(self):
        user_id, user = self.get_user()
        post = self.get_post()
        template = 'blog-post-page.html'
        new_subject = self.request.get("subject")
        new_post = self.request.get("post")
        params = {'user': user, 'subject': new_subject, 'post': new_post}
        error = None
        redirect = None

        if not user:
            self.redirect('/blog/login')
        else:
            redirect, error = self.edit_post_store(post, user_id, new_subject,
                                                   new_post)

        if error:
            params['error'] = error

        if redirect:
            self.redirect(redirect)
        else:
            post = self.get_post()
            params['post'] = post
            self.render(template, **params)


class Permalink(MainHandler, PostsHandler, LikesHandler, CommentsHandler):
    '''Permalink page - page that renders single post and comments. Is redirected
    to after: a post is created, a post is edited, a comment is created, or a
    comment is edited.'''
    def get(self):
        user_id, user = self.get_user()
        post = self.get_post()
        template = 'blog-permalink.html'
        params = {'user': user, 'post': post}

        if post:
            self.render(template, **params)
        else:
            self.error(404)
            return

    def post(self):
        user_id, user = self.get_user()
        post = self.get_post()
        (like, comment, delete_comment, edit_comment, delete_post,
            edit_post) = self.get_blog_actions()
        template = 'blog-permalink.html'
        params = {'user': user, 'post': post}
        error = None
        redirect = None

        if not user:
            error = 'You must log in to act on posts'
        else:
            if like:
                error = self.like(like, user_id)

            elif comment:
                redirect = '/blog/com/?postid=%s' % comment

            elif delete_comment:
                error = self.delete_comm(user, delete_comment)

            elif edit_comment:
                redirect, error = self.edit_comm_redirect(user, edit_comment)

            elif delete_post:
                redirect, error = self.delete_post(delete_post, user_id)

            elif edit_post:
                redirect, error = self.edit_post_redirect(edit_post, user_id)

        if error:
            params['error'] = error

        if not redirect:
            post = self.get_post()
            params['post'] = post
            self.render(template, **params)
        else:
            self.redirect(redirect)


class Comment(MainHandler, PostsHandler, LikesHandler, CommentsHandler):
    '''Posts new comments on blog posts.'''
    def get(self):
        user_id, user = self.get_user()
        post = self.get_post()
        template = 'blog-new-comment-page.html'
        params = {'user': user, 'post': post, 'comment': ''}

        if post:
            self.render(template, **params)
        else:
            self.error(404)
            return

    def post(self):
        user_id, user = self.get_user()
        post = self.get_post()
        (like, comment, delete_comment, edit_comment, delete_post,
            edit_post) = self.get_blog_actions()
        template = 'blog-new-comment-page.html'
        params = {'user': user, 'post': post, 'comment': comment}
        error = None
        redirect = None

        if not user:
            error = 'You must log in to act on posts'
        else:
            if like:
                error = self.like(like, user_id)

            elif comment:
                redirect = self.add_comm(post, user, comment)

            elif delete_comment:
                error = self.delete_comm(user, delete_comment)

            elif edit_comment:
                redirect, error = self.edit_comm_redirect(user, edit_comment)

            elif delete_post:
                redirect, error = self.delete_post(delete_post, user_id)

            elif edit_post:
                redirect, error = self.edit_post_redirect(edit_post, user_id)

        if error:
            params['error'] = error

        if not redirect:
            post = self.get_post()
            params['post'] = post
            self.render(template, **params)
        else:
            self.redirect(redirect)


class EditComment(MainHandler, PostsHandler, LikesHandler, CommentsHandler):
    '''Page to edit existing comments'''
    def get(self):
        user_id, user = self.get_user()
        exist_comment = self.request.get('exist_comment')
        exist_comment_text = exist_comment.split('|')[0]
        post = Blog.get_by_id(int(exist_comment.split('|')[-1]))
        template = 'blog-edit-comment-page.html'
        params = {'user': user, 'post': post,
                  'comment_change': exist_comment_text}

        if post:
            self.render(template, **params)
        else:
            self.error(404)
            return

    def post(self):
        user_id, user = self.get_user()
        exist_comment = self.request.get('exist_comment')
        post = Blog.get_by_id(int(exist_comment.split('|')[-1]))
        (like, comment, delete_comment, edit_comment, delete_post,
            edit_post) = self.get_blog_actions()
        comment_change = self.request.get('comment_change')
        template = 'blog-edit-comment-page.html'
        params = {'user': user, 'post': post, 'comment_change': comment_change}
        error = None
        redirect = None

        if not user:
            error = 'You must log in to act on posts'
        else:
            if like:
                error = self.like(like, user_id)

            elif comment:
                redirect = '/blog/com/?postid=%s' % comment

            elif delete_comment:
                error = self.delete_comm(user, delete_comment)

            elif edit_comment:
                redirect, error = self.edit_comm_redirect(user, edit_comment)

            elif comment_change:
                redirect, error = self.edit_comm_post(user, exist_comment,
                                                      comment_change)

            elif delete_post:
                redirect, error = self.delete_post(delete_post, user_id)

            elif edit_post:
                redirect, error = self.edit_post_redirect(edit_post, user_id)

        if error:
            params['error'] = error

        if not redirect:
            self.render(template, **params)
        else:
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
                               ('/blog/edit-post/', EditPost),
                               ('/blog/com/', Comment),
                               ('/blog/edit-com/', EditComment),
                               ('/blog/pl/', Permalink),
                               ('/blog/login', Login),
                               ('/blog/logout', Logout)
                               ],
                              debug=True)
