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
import os
import webapp2
import jinja2
import random
import hashlib
import re
import logging
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
							   autoescape = True)
							   
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
TOOL_BAR = '<p class="toolbar"> <a href="/_edit/%pagename/">edit</a> | history spez(<a href="/logout">logout</a>) </p>'
VIEW_TOOL_BAR = '<p class="toolbar"> <a href="/../%pagename/">edit</a> | history spez(<a href="/logout">logout</a>) </p>'
DEBUG = True
def valid_username(username):
	return USER_RE.match(username)
def valid_password(password):
	return PASSWORD_RE.match(password)
def valid_email(email):
	return EMAIL_RE.match(email)
	
class User(db.Model):
	#username and password table
	#username # H(password + salt),salt
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)

def make_salt():
	salt_length = 5
	salt = ""
	letters = range(65,91) # get cap letters
	letters += range(97,123) # get lowercase letters
	for i in range(salt_length):
		salt += chr(random.choice(letters))
	return salt
	
def make_hash(s):
	return hashlib.sha256(s).hexdigest()
	
def make_pw_hash(pw, salt=""):
	if salt == "":
		salt = make_salt()
	return make_hash(pw+salt) + "," + salt

def validate_pw(pw, h):
	salt = h.split(",")[1]
	hash = make_pw_hash(pw, salt)
	return hash == h
	
class Handler(webapp2.RequestHandler):
		
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)
		
	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))
		
class Welcome(webapp2.RequestHandler):
	def get(self):
		username = self.request.cookies.get("username")
		if username:
			#username = self.request.get("username")
			self.response.out.write(welcome_page % { "username": username } )
		else:
			self.redirect("/signup")

class Signup(Handler):
	def render_page(self, username="", email="", uerror="", perror="", verror="", eerror=""):
		#username = "cookie"
		self.render("signup.html", username=username, email=email, uerror=uerror, 
					perror=perror, verror=verror, eerror=eerror)
	def get(self):
		self.render_page()
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		varify = self.request.get("verify")
		email = self.request.get("email")
		uerror = ""
		perror = ""
		verror = ""
		eerror = ""
		okay = True
		
		if not valid_username(username):
			uerror = "This is not a valid Username."
			okay = False
		if not valid_password(password):
			perror = "That was not a valid Password."
			okay = False
		if not valid_email(email):
			eerror = "This is not a valid Email"
			#okay = False
		if not (password == varify):
			verror = "The passwords did not match."
			okay = False
		if okay:
			# in production version the username should also come paried with a hash
			# to increase security
			self.response.headers.add_header('Set-Cookie', "username=%s;Path=/" % str(username) )

			u = User(username = username, password = make_pw_hash(password))
			u.put()
			self.redirect("/")
			
		else:
			
			self.render_page( username, email, uerror, perror, verror, eerror)

class Login(Handler):
	def render_page(self, username="",  error=""):
		self.render("login.html", username=username, error=error)
	def get(self):
		self.render_page()
	def post(self):
		username = self.request.get("username")
		password = self.request.get("password")
		if username <> "" and password <> "":
			users = db.GqlQuery("SELECT * FROM User WHERE username =:1 LIMIT 1",username)
			user = users.get()
			if(user <> None): # check if user exists in the db
				if validate_pw(password, user.password):
					self.response.out.write("valid")
					self.response.headers.add_header('Set-Cookie', "username=%s;Path=/" % str(username) )
					self.redirect("/")
				self.render_page(username, "Invalid login")
			else:
				self.render_page(username,"Invalid login")
		else:
			self.render_page(username, "You must enter a username and password")
			
class Logout(webapp2.RequestHandler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'username=;visits=;Path=/' )
		self.redirect('/signup')



class Page(db.Model):
	url = db.StringProperty(required = True)
	page_html = db.TextProperty(required = True)
	creator_id = db.IntegerProperty(required = True)
	version = db.IntegerProperty(required = False)
	submitted = db.DateTimeProperty(auto_now_add = True)
	
#log out clears user cookies and redirects back to page they were on
#users cant creat a username same as one that already exists
# history  login | signup
def make_toolbar(user="",editing=False, page_link=""):
	history = '<a href="/_history%s">history</a>' % page_link
	if user:
		if editing:
			toolbar = '<p class="toolbar"><a href="%s">view</a> | %s ' % (page_link, history)
		else :
			toolbar = '<p class="toolbar"><a href="/_edit%s">edit</a> | %s ' % (page_link, history)
		toolbar += '%s (<a href="/logout">logout</a>)</p>' % user
	else :
		toolbar = '<p class="toolbar"><a href="%s">view</a>|%s <a href="/login">login</a>|<a href="/signup">signup</a></p>' % (page_link, history)
	return toolbar
	
class EditPage(Handler):
	def render_page(self, toolbar="", page_html=""):
		self.render("editpage.html", toolbar=toolbar, page_html=page_html)
		
	def get(self, page_url):
		#view(or edit)|history spez(logout)
		version = self.request.get("v")
		username = self.request.cookies.get("username")
		if username:
			toolbar = make_toolbar(username, True, page_url)
			if version:
				p = db.GqlQuery("SELECT * FROM Page Where url = :1 AND version = :2 limit 1", page_url, int(version))
				page = p.get()
				if not page:
					self.redirect('/_edit'+page_url)
					return
			else:
				p = db.GqlQuery("SELECT * FROM Page Where url = :1 ORDER BY submitted DESC limit 1", page_url)
			page = p.get()
			page_html = ""
			if page:
				
				page_html = page.page_html
			self.render_page(toolbar, page_html)
			#edit form
			# - textarea
			#submit button
		else:
			self.redirect("/signup")
	def post(self, page_url):
		#need to check if logged in.
		url = page_url
		username = self.request.cookies.get("username")
		if username:
			page_html = self.request.get("content")
			creator_id = 20 # get_user_id(username)
			p = db.GqlQuery("SELECT * FROM Page WHERE url = :1 ORDER BY submitted Desc LIMIT 1", page_url)
			page = p.get()
			
			if page: #if page already exists use the old one and just update page_html
				new_version = page.version + 1
				new_page = Page( url = page_url, page_html = page_html, creator_id = creator_id, version = new_version)
			else:
				new_page = Page(url = url, page_html = page_html, creator_id = creator_id, version=1)
			new_page.put()
				
			self.redirect(page_url)
		else:
			self.redirect("/signup")
	
class WikiPage(Handler):
	def render_page(self, toolbar, page_html):
		self.render("wikipage.html", toolbar=toolbar, page_html=page_html)
	def get(self, page_url):
		
		#users = db.GqlQuery("SELECT * FROM User WHERE username =:1 LIMIT 1",username)
		logging.error(page_url)
		version = self.request.get("v")
		logging.error(version)
		if version:
			p = db.GqlQuery("SELECT * FROM Page WHERE url =:1 AND version = :2",page_url, int(version))
			
		else:
			p = db.GqlQuery("SELECT * FROM Page WHERE url =:1 ORDER BY submitted Desc",page_url)
		page = p.get()
		logging.error(page)
		
		
		username = self.request.cookies.get("username")
		
		if page:
			
			toolbar = make_toolbar(username,False,page_url)
			page_html = page.page_html
			self.render_page(toolbar, page_html)
		else:
			if username:
				self.redirect('/_edit'+page_url)
			else:
				self.redirect('/signup')
		#self.redirect('/_edit'+page_url)
		#if page exists display it from cache
		#else redirect to /_edit/page
class HistoryPage(Handler):
	def render_page(self, toolbar, pages):
		self.render("historypage.html", toolbar=toolbar, pages=pages)
	def get(self, page_url):
		ps = db.GqlQuery("SELECT * FROM Page WHERE url =:1 ORDER BY submitted Desc",page_url)
		#ps = ps.get()
		pages = []
		ps = list(ps)
		logging.error("ps es" + str(ps))
		
		for p in ps:
			
			logging.error("the P" + str(p))
			logging.error(" THIS IS THE PAGE HTML " + p.page_html)
			page = [] # indexes
			page.append( p.submitted ) # 0
			page.append( str(p.page_html)[0:200] ) #1
			
			if  p.version:
				page.append( '<a href="%s?v=%s">view</a>' % (p.url, p.version)) # 2
				page.append('<a href="/_edit%s?v=%s">edit</a>' % (p.url, p.version)) #3
			else :
				page.append( '<a href="%s">view</a>' % p.url ) #2
				page.append('<a href="/_edit%s">edit</a>' % p.url ) # 3
			pages.append( page)
		username = self.request.cookies.get("username")
		toolbar = make_toolbar(username,False,page_url)
		logging.error("breaak time \n\n")
		for page in pages:
			logging.error(str(page))
		self.render_page(toolbar, pages) 
		###
		derp2 = """
		while p != None:
			logging.error("the P" + str(p))
			logging.error(" THIS IS THE PAGE HTML " + p.page_html)
			page = [] # indexes
			page.append( p.submitted ) # 0
			page.append( str(p.page_html)[0:21] ) #1
			
			if  p.version:
				page.append( '<a href="%s?v=%s">view</a>' % (p.url, p.version)) # 2
				page.append('<a href="/_edit/%s?v=%s">edit</a>' % (p.url, p.version)) #3
			else :
				page.append( '<a href="%s">view</a>' % p.url ) #2
				page.append('<a href="/_edit/%s">edit</a>' % p.url ) # 3
			pages += page
			p = ps.get()
		
		toolpar = "derpbar"
		self.render_page(toolbar, pages) """


class Welcome(Handler):
	def get(self):
		#self.response.headers.add_header('Set-Cookie', "username=%s;Path=/" % str("Subarashii") )
		username = self.request.cookies.get("username")
		self.response.out.write("%s, Welcome to super-simple Wiki!" % username)
		
		page = Page(url = "/doggies/", page_html = '<b>woof im 3</b>', creator_id = 20, version = 3)
				
		page.put()
class MainHandler(webapp2.RequestHandler):
    def get(self):
		
        self.response.out.write('Hello world!')

app = webapp2.WSGIApplication([('/signup', Signup),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/_edit' + PAGE_RE, EditPage),
							   ('/_history' + PAGE_RE, HistoryPage),
							   ('/welcome', Welcome),
                               (PAGE_RE, WikiPage)
							   
                               ],
                              debug=DEBUG)
