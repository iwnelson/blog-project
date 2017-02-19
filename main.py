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
import datetime  # will use later to correct time zone to eastern standard time
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
    '''General Handler functions'''
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

    def login(self, user_id):
        '''Takes user_id(must exist in UserInfo) and adds secure hmac cookie
        for it'''
        user_id = str(user_id.key().id())
        self.set_secure_cookie('user_id', user_id)

    def logout(self):
        '''Overwrites user_id function with None value'''
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class RetrieveVarsHandler(MainHandler):
    """functions that retrieve variables from cookies/url for blog"""
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
        return like, comment, delete_comment, edit_comment, delete_post,
        edit_post


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
        post_id_str = str(p.key().id())
        return post_id_str

    def edit_post(self, post, user_id, new_subject, new_post):
        '''Edits exising post & subject and stores new vals to Blog Database'''
        if post.user_id != int(user_id):
            error = 'You can only edit your own posts'
            return error
        else:
            post.subject = new_subject
            post.post = new_post
            post.put()
            post_id_str = str(post.key().id())
            return post_id_str


class LikesHandler():
    """Contains function to like/unlike post & store data to Blog database
    including permission check"""
    def like(self, post, user_id):
        if int(user_id) == post.user_id:
            error = 'You cannnot like your own post, you egomaniac.'
            return error
        elif user_id in post.liked_by:
            post.liked_by.remove(user_id)
            post.likes += -1
            post.put()
        elif user_id not in post.liked_by:
            post.likes += 1
            post.liked_by.append(user_id)
            post.put()


class CommentsHandler():
    """Contains functions to add, edit, and delete comments"""
    def add_comm(self, post, user, comment):
        username = user.username
        post_id_str = str(post.key().id())
        post.comments.append(comment + '|' + username + '|' + post_id_str)
        post.put()

    def edit_comm(self, user, exist_comment, comment_change):
        post_id = exist_comment.split('|')[-1]
        post = Blog.get_by_id(int(post_id))
        exist_comment_user = exist_comment.split('|')[-2]
        username = user.username
        if username != exist_comment_user:
            error = 'You can only edit your own comments.'
            return error
        else:
            comment_index = post.comments.index(exist_comment)
            new_comment = comment_change + '|' + username + '|' + post_id
            post.comments[comment_index] = new_comment
            post.put()

    def delete_comm():
        pass



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











# blog main page that lists entries
class BlogMain(MainHandler):
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
class NewPost(MainHandler):
    def get(self):
        user_id = self.read_secure_cookie('user_id')
        if not user_id:
            self.redirect('/blog/login')
        else:
            self.render('blog-post-page.html')

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
            self.render('blog-post-page.html', subject = subject,
                        post = post, error = error)

# edit post page
class EditPost(MainHandler):
    def get(self):
        user_id = self.read_secure_cookie('user_id')
        post_id = self.request.get('postid')
        post_to_edit = Blog.get_by_id(int(post_id))
        if not user_id:
            self.redirect('/blog/login')
        else:
            self.render('blog-post-page.html',
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
            self.render('blog-post-page.html', subject = subject,
                        post = post, error = error)
        elif post_to_edit.user_id != int(user_id):
            error = 'You can only edit your own posts'
            self.render('blog-post-page.html', subject = subject,
                        post = post, error = error)
        elif post_to_edit.user_id == int(user_id):
            post_to_edit.subject = subject
            post_to_edit.post = post
            post_to_edit.put()
            self.redirect('/blog/pl/?postid=%s' %
                            str(post_to_edit.key().id()))

# permalink page
class Permalink(MainHandler):
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
class Comment(MainHandler):
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
class EditComment(MainHandler):
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

        self.render('blog-comment-page.html', post = post,
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
                self.render('blog-comment-page.html', post = post,
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
                self.render('blog-comment-page.html', post = post,
                        comment = comment_text, user_id = user_id)

            elif like and user_id:
                post.likes += 1
                post.liked_by.append(user_id)
                post.put()
                self.render('blog-comment-page.html', post = post,
                        comment = comment_text, user_id = user_id)

        # redirects to comment on posts page with validity checks
        if comment:
            if not user_id:
                error = 'You must log in to comment on posts.'
                self.render('blog-comment-page.html', post = post,
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
class UserSignup(MainHandler):
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
class WelcomePage(MainHandler):
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
class Login(MainHandler):
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
class Logout(MainHandler):
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





