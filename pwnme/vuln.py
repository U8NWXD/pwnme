import functools

from flask import (
    redirect, render_template, request, Blueprint, url_for, g, session)

from pwnme import base
from pwnme.base import Site
from pwnme.db import get_db


bp = Blueprint('vuln', __name__, url_prefix='/vuln')


@bp.route('/')
def index():
    return render_template('index_vuln.html')


@bp.route('/hello/')
def hello():
    '''Says hello to a user.

    The user's name is specified as a URL argument ``name``.

    The ``hello_vuln.html`` template used by this endpoint disables
    Jinja2's automatic escaping of arguments. This allows a reflected
    XSS attack when the ``name`` argument contains code. For example,
    try submitting a name of ``<script>alert(1);</script>`` from
    ``/vuln/whoami``.

    By default, Flask enables Jinja2's automatic escaping for many
    files. See the
    `https://flask.palletsprojects.com/en/1.1.x/templating/#jinja-setup
    <Flask documentation>`_ for details. You can also find more
    information on Jinja2's escaping on
    `https://jinja.palletsprojects.com/en/master/templates/#html-escaping
    <this page of Jinja2's documentation>`_.
    '''
    name = request.args.get('name')
    return render_template('hello_vuln.html', name=name)


@bp.route('/whoami/', methods=('GET', 'POST'))
def whoami():
    '''Simple webform that accepts a user's name.

    Redirects the user to a vulnerable greeting page.
    '''
    return base.whoami(Site.VULN)


@bp.before_app_request
def load_logged_in_user():
    base.load_logged_in_user()


@bp.route('/register/', methods=('GET', 'POST'))
def register():
    return base.register(Site.VULN)


@bp.route('/login/', methods=('GET', 'POST'))
def login():
    return base.login(Site.VULN)


@bp.route('/logout/')
def logout():
    return base.logout(Site.VULN)


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('vuln.login'))

        return view(**kwargs)

    return wrapped_view


@bp.route('/hidden/')
def hidden():
    return render_template('hidden_vuln.html')


@bp.route('/view-balance/')
@login_required
def view_balance():
    balance = base.get_balance()
    return render_template('view_balance_vuln.html', balance=balance)


@bp.route('/withdraw/', methods=('GET', 'POST'))
@login_required
def withdraw():
    if request.method == 'POST':
        amount = float(request.form['amount'])
        balance = base.get_balance()
        new_balance = balance - amount
        base.update_balance(new_balance)
        return redirect(url_for('vuln.index'))
    return render_template('withdraw_vuln.html')


@bp.route('/lookup_user/', methods=('GET', 'POST'))
@login_required
def lookup_user():
    user_id = None
    if request.method == 'POST':
        username = request.form['user']
        db = get_db()
        # executescript() allows for multiple commands
        user = db.executescript(
            f'SELECT * FROM user WHERE username = "{username}"'
        ).fetchone()
        # This isn't really needed, but I needed to use executescript(),
        # which doesn't seem to work with fetchone(), to make fun SQL
        # injections possible.
        if not user:
            user = db.execute(
                f'SELECT * FROM user WHERE username = "{username}"'
            ).fetchone()
        if user:
            user_id = int(user['id'])
    return render_template('lookup_vuln.html', user_id=user_id)
