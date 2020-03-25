#!/usr/bin/env python

import flask
import json
import os
import sys
import sqlite3
import hashlib

from flask import (
  render_template, g, url_for, request, flash, redirect, session
)
from pathlib import Path
from functools import wraps

PATH_DB = Path('db_dnd.sqlite3')
PATH_DB_USERS = Path('db_dnd_users.sqlite3')

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
  if username == "admin" and password == "password":
    return True
  return False

def app_get():

  app = flask.Flask(__name__)
  app.secret_key = 'arsotin23oy8n3;9nasrt09larst'

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
      else:
        flash(f'Wrong username or password.')
    if 'password' in form:
      del form['password']
    return render_template('login.html', form=form)

  @app.route('/signup')
  def signup():
    return render_template('signup.html')

  @app.route('/logout', methods=['GET'])
  def logout():
    for field in ['username','logged_in']:
      if field in session:
        session.pop(field)
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
