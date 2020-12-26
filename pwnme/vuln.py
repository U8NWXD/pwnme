import functools

from flask import (
    redirect, render_template, request, Blueprint, url_for, g)

from pwnme import base
from pwnme.base import Site


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
