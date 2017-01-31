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
import cgi
import re
import webapp2

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def build_main_page(username_holdover,
                    email_holdover,
                    username_msg,
                    pswd_msg,
                    verify_msg,
                    email_msg):

        header = "<h2>Signup</h2>"

        username_label    = "<label>Username: </label>"
        username_input    = ("<input type='text' name='username' value='" + username_holdover +"'/>")

        pswd_label        = "<label>Password: </label>"
        pswd_input        = "<input type='password' name='password' value=''/>"

        verify_pswd_label = "<label>Verify password: </label>"
        verify_pswd_input = "<input type='password' name='verify' value=''/>"

        email_label       = "<label>E-mail (optional): </label>"
        email_input       = ("<input type='text' name='email' value='" + email_holdover +"'/>")

        submit = "<input type='submit'/>"

        form = ("<form method='post'>" +
            "<table>" +
            "<tr><td class='label'>" + username_label + "</td>" +
            "<td>" + username_input + "</td>" +
            "<td class='error_message'><em><font color=red>" + username_msg + "</font></em></td></tr>" +
            "<tr><td class='label'>" + pswd_label + "</td>" +
            "<td>" + pswd_input + "</td>" +
            "<td class='error_message'><em><font color=red>" + pswd_msg + "</font></em></td></tr>" +
            "<tr><td class='label'>" + verify_pswd_label + "</td>" +
            "<td>" + verify_pswd_input + "</td>" +
            "<td class='error_message'><em><font color=red>" + verify_msg + "</font></em></td></tr>" +
            "<tr><td class='label'>" + email_label + "</td>" +
            "<td>" + email_input + "</td>" +
            "<td class='error_message'><em><font color=red>" + email_msg + "</font></em></td></tr>" +
            "<tr><td></td><td>" + submit + "</td></tr></table></form>")

        return header + form

def build_welcome_page(username):
    content = "<h2>Welcome, "+ username + "!<h2>"
    return content

class Signup(webapp2.RequestHandler):
    def get(self):
        content = build_main_page("", "", "", "", "", "")
        self.response.write(content)

    def post(self):
        have_error = False

        username           = self.request.get('username')
        password           = self.request.get('password')
        verify             = self.request.get('verify')
        email              = self.request.get('email')

        escaped_username   = cgi.escape(username, quote=True)
        escaped_password   = cgi.escape(password, quote=True)
        escaped_verify     = cgi.escape(verify, quote=True)
        escaped_email      = cgi.escape(email, quote=True)

        username_error_msg = ""
        password_error_msg = ""
        verify_error_msg   = ""
        email_error_msg    = ""

        if not valid_username(escaped_username):
            have_error = True
            username_error_msg = "That's not a valid username."

        if not valid_password(escaped_password):
            have_error = True
            password_error_msg = "That's not a valid password."
        elif escaped_password != escaped_verify:
            have_error = True
            verify_error_msg = "Your passwords don't match."

        if not valid_email(escaped_email):
            have_error = True
            email_error_msg = "That's not a valid email."

        if have_error:
            content = build_main_page(escaped_username, escaped_email, username_error_msg, password_error_msg, verify_error_msg, email_error_msg)
            self.response.write(content)
        else:
            self.redirect('/welcome?username=' + escaped_username)

class Welcome(webapp2.RequestHandler):
    def get(self):
        username = self.request.get('username')
        escaped_username = cgi.escape(username, quote=True)
        if valid_username(escaped_username):
            content=build_welcome_page(escaped_username)
            self.response.write(content)
        else:
            self.redirect('/signup')

app = webapp2.WSGIApplication([
    ('/signup', Signup),
    ('/welcome', Welcome)
    ], debug=True)
