#!/usr/bin/env python

from datetime import datetime, timedelta
from functools import wraps, reduce
import json
import operator
import regex
import sys
from uuid import UUID

import flask
from flask import Flask, g, session, url_for, Response
from flask import render_template, request, redirect, abort

import ucam_webauth
import raven
import raven.flask_glue

from .lib.send_email import email as send_email
from .model import (db, fn, JOIN,
    Person, Invite, AUTH_TYPES,
    RavenAuth, get_real_name,
    EmailAuth, AuthToken, random_token,
    MinecraftInfo, Server
)

sys.path.append('/societies/minecraft/bin/lib')
try:
    from rcon import rcon_init
except ImportError:
    class Rcon:
        def request(self, cmd):
            words = cmd.split(" ")
            if cmd.startswith("whitelist add"):
                return "Added " + words[2] + " to the whitelist"
            pass
    rcon = Rcon()
else:
    rcon = rcon_init('/societies/minecraft/forge-server')


ADMIN_EMAIL = "Minecraft Admins <admins@example.com>", # TODO config
PRIVATE_HOSTS = {
    # a list of trusted hosts, eg the minecraft server box
    '127.0.0.1', # localhost
    #'10.100.64.65',
}

app = Flask(__name__)
app.secret_key = '' # TODO sane config

app.config['TRAP_BAD_REQUEST_ERRORS'] = True

@app.before_request
def _db_connect():
    db.connect()

@app.teardown_request
def _db_close(exc):
    if not db.is_closed():
        db.close()

#------------------------------------------------------------------------------

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(weeks=100)

@app.context_processor
def mailto_link():
    return dict(
        # TODO config
        admin_email = "mailto:___", # URL-encoded email address
    )

#------------------------------------------------------------------------------

# Homepage

@app.route("/")
def home():
    return render_template("home.html")

#------------------------------------------------------------------------------

# Raven login

class R(flask.Request):
    trusted_hosts = {
        'localhost',
        # ... our TLD ...
        # TODO config
    }
app.request_class = R

auth_decorator = raven.flask_glue.AuthDecorator(
    require_ptags=None,
)

@app.route("/login/raven/")
@auth_decorator
def raven_login():
    # Raven authenticated
    crsid = auth_decorator.principal
    assert crsid
    with db.transaction():
        try:
            auth = RavenAuth.get(principal=crsid)
        except RavenAuth.DoesNotExist:
            # New user: register them.
            person = Person.create()
            real_name = get_real_name(crsid)
            auth = RavenAuth.create(
                person = person,
                principal = crsid,
                real_name = real_name,
            )
    set_auth(auth)
    return post_login_redirect(auth.person)

#------------------------------------------------------------------------------

# Email login

def is_valid_email(email):
    return '@' in email and len(email) > 3

def send_login_email(email):
    try:
        auth = EmailAuth.get(email=email)
    except EmailAuth.DoesNotExist:
        # Not registered yet.
        # If they're a student, they should use Raven instead.
        # Otherwise, students can email us to ask for their friends to join.
        return False
    send_login_auth(auth)
    return True

def send_login_auth(auth):
    auth_token = AuthToken.create(auth=auth)
    contents = render_template("login_email_auth.txt",
        token = auth_token.token,
        host = app.config['SERVER_NAME'],
    )
    send_email(contents,
        subject = "CU Minecraft login",
        to = "{} <{}>".format(auth.person.real_name, auth.email),
    )

@app.route("/login/email/", methods=["GET", "POST"])
def login_email():
    if request.method == 'POST':
        email = request.form.get('email', "").strip()
        is_sent = send_login_email(email)
        return render_template("login_email.html",
            email = email,
            is_sent = is_sent,
            is_cam_email = email.endswith('@cam.ac.uk'),
        )
    return render_template("login_email.html")

@app.route("/auth/<token>")
def email_auth(token):
    try:
        auth_token = (AuthToken.select().where(AuthToken.token==token)
                                        .join(EmailAuth).join(Person).get())
    except AuthToken.DoesNotExist:
        return redirect(url_for('login_menu'))
    auth = auth_token.auth
    set_auth(auth)
    return post_login_redirect(auth.person)

#-------------------------------------------------------------------------------

# Auth

@app.route("/login/")
def login_menu():
    auth = get_auth()
    if auth:
        return post_login_redirect(auth.person)
    return render_template("login.html")

@app.route("/logout/")
def logout():
    clear_auth()
    return redirect(url_for('login_menu'))

def set_auth(auth):
    session['auth_id'] = auth.id
    session['auth_type'] = auth.__class__.__name__

def post_login_redirect(person):
    if not has_played(person):
        return redirect(url_for('welcome'))
    else: 
        return redirect(url_for('profile'))

def get_auth():
    """Return Auth from session, or None"""
    auth_id = session.get('auth_id')
    if not auth_id:
        return
    auth_type = session.get('auth_type')
    auth_cls = AUTH_TYPES.get(auth_type)
    if not auth_cls:
        return
    try:
        auth = auth_cls.get(id=auth_id)
    except auth_cls.DoesNotExist:
        return
    g.auth = auth
    g.person = auth.person
    return auth

def clear_auth():
    session['auth_id'] = None
    session['auth_type'] = None

def _with_person(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        if not get_auth():
            clear_auth()
            return redirect(url_for('login_menu'))
        g.person.last_visit = datetime.now()
        g.person.save()
        return func(*args, **kwargs)
    return decorated_view

def with_admin(func):
    @wraps(func)
    @_with_person
    def decorated_view(*args, **kwargs):
        if not g.person.is_admin:
            abort(403)
        return func(*args, **kwargs)
    return decorated_view

#-------------------------------------------------------------------------------

# Admin interface for
# - adding friends by email
# - updating server URL

def email_exists(email):
    try:
        EmailAuth.get(email=email)
        return True
    except EmailAuth.DoesNotExist:
        return False

def create_email_person(friend, email, real_name):
    invite = Invite.create(invited_by=friend)
    new_person = Person.create(real_name=real_name, invite=invite)
    auth = EmailAuth.create(person=new_person, email=email)
    return auth

@app.route("/control/")
@with_admin
def control():
    return render_template('control.html')

@app.route("/control/invite/", methods=['GET', 'POST'])
@with_admin
def control_invite():
    success = session.get('resend_success', False)
    if success:
        session.pop('resend_success')
    crsid = ""
    email = ""
    real_name = ""
    error = ""
    if request.method == 'POST':
        crsid = request.form.get('crsid')
        email = request.form.get('email')
        real_name = request.form.get('real_name').strip()
        try:
            friend = RavenAuth.get(principal=crsid).person
        except RavenAuth.DoesNotExist:
            error = "CRSid does not exist."
        else:
            if email_exists(email):
                error = "Email already exists. Maybe resend?"
            else:
                auth = create_email_person(friend, email, real_name)
                send_invite_auth(friend, auth)
                success = email
                crsid = ""
                email = ""
                real_name = ""
    resend_error = session.get('resend_error', "")
    if resend_error:
        session.pop('resend_error')
    return render_template('control_invite.html',
        success = success,
        error = error,
        crsid = crsid,
        email = email,
        real_name = real_name,
        resend_error = resend_error,
    )

@app.route("/control/invite/resend/", methods=['POST'])
@with_admin
def control_resend():
    email = request.form.get('email')
    if not email_exists(email):
        session['resend_error'] = "Email does not exist. Invite them!"
        return redirect(url_for('control_invite'))

    auth = EmailAuth.get(email=email)
    person = auth.person
    if person.has_joined:
        session['resend_error'] = "User has already joined."
        return redirect(url_for('control_invite'))
    if not person.invite:
        session['resend_error'] = "User wasn't previously invited by anyone."
        return redirect(url_for('control_invite'))

    session['resend_success'] = email
    friend = person.invite.invited_by
    send_invite_auth(friend, auth)
    return redirect(url_for('control_invite'))

def send_invite_auth(friend, auth):
    auth_token = AuthToken.create(auth=auth)
    contents = render_template("login_invite_auth.txt",
        token = auth_token.token,
        host = app.config['SERVER_NAME'],
        friend = friend,
        person = auth.person,
    )
    send_email(contents,
        subject = "CU Minecraft invite",
        to = "{} <{}>".format(auth.person.real_name, auth.email),
    )

@app.route("/control/server/", methods=['GET', 'POST'])
@with_admin
def control_server():
    server = Server.get()
    if request.method == 'POST':
        address = request.form.get('address')
        if address:
            server.address = address
            server.save()
        return redirect(url_for('control_server'))
    return render_template('control_server.html',
        server=server,
    )

def notify_admins(template_name, subject=None, reply_to=None, **kwargs):
    contents = render_template(template_name, **kwargs)
    send_email(contents,
        subject = subject,
        to = ADMIN_EMAIL,
        reply_to = reply_to,
    )

#-------------------------------------------------------------------------------

def has_joined(person):
    return person.has_joined

def with_known_person(func):
    @wraps(func)
    @_with_person
    def decorated_view(*args, **kwargs):
        if not has_joined(g.person):
            return redirect(url_for('join'))
        return func(*args, **kwargs)
    return decorated_view

def with_new_person(func):
    @wraps(func)
    @_with_person
    def decorated_view(*args, **kwargs):
        if has_joined(g.person):
            return post_login_redirect(g.person)
        return func(*args, **kwargs)
    return decorated_view

# Welcome flow

word_re = regex.compile(r' +')
def split_words(text):
    return [w for w in word_re.split(text) if w]

def is_word(word):
    return len(word) > 1 and '.' not in word

def is_full_name(name):
    words = split_words(name)
    return len(words) > 1 and all(is_word(w) for w in words)

def join_person(person, real_name, signature):
    person.real_name = real_name
    person.signature = signature
    person.has_joined = True
    person.join_time = datetime.now()
    person.save()

    try:
        crsid = person.raven_auths.get().principal
    except RavenAuth.DoesNotExist:
        crsid = None
    try:
        email = person.email_auths.get().email
    except EmailAuth.DoesNotExist:
        email = None
    notify_admins("notify_join.txt",
        subject = "{} joined".format(real_name),
        crsid = crsid,
        email = email,
        person = person,
        reply_to = email or "{}@cam.ac.uk".format(crsid),
    )

    return redirect(url_for('welcome'))

def has_played(person):
    return getattr(person.minecraft, 'last_login', None) != None

@app.route("/join/", methods=['GET', 'POST'])
@with_new_person
def join():
    signature = ""
    real_name = getattr(g.person, 'real_name', getattr(g.auth, 'real_name', "")).strip()
    real_name_error = False
    if request.method == 'POST':
        real_name = request.form.get('real_name', "").strip()
        signature = request.form.get('signature', "")
        if signature and is_full_name(real_name):
            return join_person(g.person, real_name, signature)
        real_name_error = True
    return render_template("join.html", 
        real_name = real_name,
        real_name_error = real_name_error,
        signature = signature,
    )

#-------------------------------------------------------------------------------

# Profile page

@app.route("/welcome/")
@with_known_person
def welcome():
    just_updated = session.get('updated_username')
    if just_updated:
        session.pop('updated_username')
    username_in_use = session.get('username_in_use')
    if username_in_use:
        session.pop('username_in_use')
    username_invalid = session.get('username_invalid')
    if username_invalid:
        session.pop('username_invalid')
    return render_template("welcome.html",
        server = Server.get(),
        minecraft_username = getattr(g.person.minecraft, 'username', ""),

        show_username = just_updated,
        username_in_use = username_in_use,
        username_invalid = username_invalid,
        has_played = has_played(g.person),
    )

def is_valid_username(username):
    return username and MinecraftInfo.NAME_RE.match(username)

def update_whitelist(old_info, new_info):
    if old_info:
        name = old_info.username
        message = rcon.request('whitelist remove {}'.format(name))
        assert message in (
            "Removed {} from the whitelist".format(name),
            "Could not remove {} from the whitelist".format(name), # seems to mean "it wasn't present"
        ), message
    if new_info:
        name = new_info.username
        message = rcon.request('whitelist add {}'.format(name))
        assert message in (
            "Added {} to the whitelist".format(name),
        ), message

def update_username(new_username):
    if not new_username:
        g.person.minecraft = None
        g.person.save()
    elif not is_valid_username(new_username):
        session['username_invalid'] = new_username
    else:
        old_info = g.person.minecraft
        if old_info and new_username.lower() == old_info.username.lower():
            return
        # Lookup UUID & properly-capitalised username
        new_info = MinecraftInfo.get_by_username(new_username)
        if not new_info:
            session['username_invalid'] = new_username
        else:
            with db.transaction():
                # is this Minecraft user in use already?
                try:
                    Person.get(minecraft=new_info)
                except Person.DoesNotExist:
                    g.person.minecraft = new_info
                    g.person.save()
                    update_whitelist(old_info, new_info)
                else:
                    session['username_in_use'] = new_info.username

@app.route("/profile/username/", methods=['POST'])
@with_known_person
def profile_username():
    new_username = request.form.get('username', "").strip()
    update_username(new_username)
    if (
        request.form.get('redirect-profile') == 'yes' and
        'username_invalid' not in session and
        'username_in_use' not in session
    ):
        return redirect(url_for('profile'))
    session['updated_username'] = True
    return redirect(url_for('welcome'))

def people_query(words):
    query = (Person.select().join(MinecraftInfo)
                            .join(RavenAuth, JOIN.LEFT_OUTER, RavenAuth.person))
    if len(words):
        query = query.where(reduce(operator.and_, [
            reduce(operator.or_, [
                fn.Lower(field).contains(word.lower())
                for field in [Person.real_name,
                              MinecraftInfo.username,
                              RavenAuth.principal]
            ])
            for word in words
        ]))
    return query


@app.route("/profile/")
@with_known_person
def profile():
    return render_template('profile.html',
        person = g.person,
        server = Server.get(),
        player_count = MinecraftInfo.select().where(MinecraftInfo.online == True).count()
    )


@app.route("/people/")
@with_known_person
def people_list():
    search = request.args.get('search', "")
    words = split_words(search)
    query = people_query(words)
    query = query.order_by(MinecraftInfo.last_login)
    people = list(query)
    for person in people:
        student = person
        if person.invite:
            student = person.invite.invited_by
        try:
            person.crsid = student.raven_auths.get().principal
        except RavenAuth.DoesNotExist:
            pass
    return render_template("people_list.html",
        has_search = True,
        is_filtered = bool(words),
        search = search,
        people = people,
        player_count = None,
    )

@app.route("/people/online/")
@with_known_person
def people_online():
    online_players = list(Person.select().join(MinecraftInfo).where(MinecraftInfo.online == True))
    return render_template("people_list.html",
        is_filtered = True,
        people = online_players,
        player_count = len(online_players),
    )

@app.route("/people/online/count.json")
@with_known_person
def online_players():
    player_count = MinecraftInfo.select().where(MinecraftInfo.online == True).count()
    return json_response(dict(
        count = player_count,
    ))


# TODO: banning

# TODO list of mods + minecraft version


#-------------------------------------------------------------------------------

# Server API

def json_response(obj):
    content = json.dumps(obj, indent=2)
    return Response(content, mimetype='application/json')

@app.route("/api/access-route.json")
def access_route():
    addresses = list(request.access_route)
    addresses.append(request.remote_addr)
    return json_response(addresses)

def with_private_host(func):
    @wraps(func)
    def decorated_view(*args, **kwargs):
        addresses = list(request.access_route)
        addresses.append(request.remote_addr)
        host = addresses[-1]
        if host not in PRIVATE_HOSTS:
            abort(403)
        return func(*args, **kwargs)
    return decorated_view

@app.route("/api/whitelist.json")
@with_private_host
def whitelist_json():
    info_list = MinecraftInfo.select().join(Person)
    whitelist = [dict(
        uuid = str(UUID(info.uuid)),
        name = info.username,
    ) for info in info_list]
    return json_response(whitelist)

@app.route("/api/real-names.json")
@with_private_host
def real_names_json():
    people = Person.select().join(MinecraftInfo)
    whitelist = [dict(
        uuid = str(UUID(person.minecraft.uuid)),
        name = person.minecraft.username,
        real_name = person.real_name,
    ) for person in people]
    return json_response(whitelist)

rcon_list_re = regex.compile(r'^There are [0-9]+/[0-9]+ players online:')

@app.route("/api/tick/minute/")
@with_private_host
def do_tick_minute():
    message = rcon.request('list')
    m = rcon_list_re.match(message)
    assert m, message
    comma_names = message[m.end():]
    user_list = comma_names.split(', ') if comma_names else []
    assert all(',' not in name for name in user_list)
    MinecraftInfo.update(online=False).where(MinecraftInfo.online == True).execute()
    for username in user_list:
        try:
            info = MinecraftInfo.get(username=username)
        except MinecraftInfo.DoesNotExist:
            pass # TODO warn
        else:
            info.online = True
            info.last_login = datetime.now()
            info.save()
    return json_response(user_list)

#-------------------------------------------------------------------------------

# TODO assert every view has a permission

