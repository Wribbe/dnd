#!/usr/bin/env python

import base64
import flask
import json
import os
import sys
import sqlite3
import hashlib
import importlib


from flask import (
  render_template, g, url_for, request, flash, redirect, session
)
from pathlib import Path
from functools import wraps

PATH_DB = Path('db_dnd.sqlite3')
PATH_DB_USERS = Path('db_dnd_users.sqlite3')
PATH_CONFIG = Path('dnd','config.py')

LEN_SALT=128

def get_db():
  db = sqlite3.connect(PATH_DB)
  db.row_factory = sqlite3.Row
  return db

def get_db_users():
  db = sqlite3.connect(PATH_DB_USERS)
  db.row_factory = sqlite3.Row
  return db

def setup_db():
  db = get_db()
  cursor = db.cursor()
  spell_data = json.loads(Path('srd_spells','spells.json').read_text())
  classes = set()
  for spell in spell_data:
    cursor.execute('INSERT INTO spells(name) VALUES (?)', (spell['name'],))
    id_spell = cursor.lastrowid
    for c in spell['classes']:
      cursor.execute('INSERT INTO classes(class, spell) VALUES (?,?)', (c, id_spell))
  db.commit()
  db.close()

def user_authenticate(username="", password=""):

  db = get_db_users()
  user = db.cursor().execute(
    "SELECT * FROM users WHERE username = (?)", (username,)
  ).fetchone()
  db.close()

  msg_err = "Wrong username or password"

  if not user:
    flash(msg_err)
    return False

  hash_stored = user['hash']
  salt, hash_password = hash_stored[:LEN_SALT], hash_stored[LEN_SALT:]
  hash_new = hash_password_get(password, salt)
  if not hash_new == hash_password:
    flash(msg_err)
    return False

  return True

def hash_password_get(password, salt):
  num = 1000000
  password = password.encode()
  return hashlib.pbkdf2_hmac('sha512', password, salt, num)

def user_create(username, password):
  salt = os.urandom(LEN_SALT)
  db = get_db_users()
  db.cursor().execute(
    "INSERT INTO users (username, hash) VALUES (?,?)",
    (username, salt+hasher)
  )
  db.commit()
  db.close()

def app_get():

  app = flask.Flask(__name__)
  if not PATH_CONFIG.is_file():
    with open(PATH_CONFIG, 'w') as fh:
      key = base64.b64encode(os.urandom(64)).decode('utf-8')
      fh.write(f'SECRET_KEY="{key}"'+os.linesep)

  config = importlib.import_module(PATH_CONFIG.stem)
  app.secret_key = config.SECRET_KEY

  def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
      if g.user is None:
        return redirect(url_for('login', next=request.url))
      return f(*args, **kwargs)
    return decorated_function

  if not PATH_DB.is_file():
    db = get_db()
    db.executescript(Path('schema.sql').read_text())
    db.commit()
    db.close()
    setup_db()

  if not PATH_DB_USERS.is_file():
    db = get_db_users()
    db.executescript(Path('schema_users.sql').read_text())
    db.commit()
    db.close()

  @app.route('/')
  def index():
    db = get_db()
    cursor = db.cursor()
    classes = [
      d['class'] for d in cursor.execute('SELECT class FROM classes').fetchall()
    ]
    db.close()
    classes = sorted({s for s in classes})
    return render_template(
      'index.html',
      classes=classes
    )

  @app.route('/login', methods=['GET','POST'])
  def login():
    form = {}
    if request.method == 'POST':
      form = dict(request.form)
      if user_authenticate(**form):
        session['username'] = form['username']
        session['logged_in'] = True
        flash(f'Successfully logged in as {form["username"]}.')
        return redirect(url_for('index'))
    if 'password' in form:
      del form['password']
    fields = [
      ("username", "text", "Username"),
      ("password", "password", "Password"),
    ]
    return render_template('login.html', form=form, fields=fields)

  @app.route('/signup', methods=['GET','POST'])
  def signup():
    form = {}
    def form_validate(form):
      len_password_min, len_password_max = [10, 1024]
      len_username_max = 25
      if len(form['username']) > len_username_max:
        flash(
          f"Username should be shorter than {len_username_max} characters."
        )
        return
      if len(form['password']) < len_password_min:
        flash(
          f"Password should be at least {len_password_min} characters long."
        )
        return
      if len(form['password']) > len_password_max:
        flash(
          f"Password should be shorter than {len_password_max} characters."
        )
        return
      if not form['username'].strip():
        flash("Please use none-whitespace characters as username.")
        return
      if not form['password'] == form['password_repeat']:
        flash("Passwords did not match, please re-enter.")
        return
      return True

    if request.method == 'POST':
      form = dict(request.form)
      if form_validate(form):
        user_create(form['username'],form['password'])

    form = {k:v for k,v in form.items() if not 'password' in k}
    fields = [
      ("username", "text", "Username"),
      ("password", "password", "Password"),
      ("password_repeat", "password", "Re-enter Password"),
    ]

    return render_template('signup.html', form=form, fields=fields)

  @app.route('/logout', methods=['GET'])
  def logout():
    for field in ['username','logged_in']:
      if field in session:
        session.pop(field)
    flash('Successfully logged out.')
    return redirect(url_for('index'))

  @app.route('/user/<username>')
  @login_required
  def user(username):
    if not g.user == username:
      return redirect(url_for('user', username=g.user))

  @app.route('/character/create')
  @login_required
  def character_create():
    return "blep"

  return app

if __name__ == "__main__":
  app = app_get()
  args = sys.argv[1:]
  debug = 'debug' in args
  if debug:
    os.environ['FLASK_ENV'] = 'development'
  app.run("0.0.0.0", debug=debug)
