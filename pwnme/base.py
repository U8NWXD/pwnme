from enum import Enum

from flask import (
	flash, g, render_template, request, redirect, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

from pwnme.db import get_db


class Site(Enum):
    SAFE = 'safe'
    VULN = 'vuln'


def whoami(site):
    if request.method == 'POST':
        name = request.form['name']
        dest = f'{site.value}.hello'
        return redirect(url_for(dest, name=name))
    return render_template(f'whoami_{site.value}.html')


def login(site):
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for(f'{site.value}.index'))

        flash(error)

    return render_template(f'login_{site.value}.html')


def register(site):
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        if error is None:
            db.execute(
                'INSERT INTO user (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            return redirect(url_for(f'{site.value}.login'))

        flash(error)

    return render_template(f'register_{site.value}.html')


def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


def logout(site):
    session.clear()
    return redirect(url_for(f'{site.value}.index'))
