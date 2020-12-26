import functools

from flask import (
    render_template, request, Blueprint, g, redirect, url_for)

from pwnme import base
from pwnme.base import Site

bp = Blueprint('safe', __name__, url_prefix='/safe')


@bp.route('/', methods=('GET',))
def index():
    return render_template('index_safe.html')


@bp.route('/hello/', methods=('GET',))
def hello():
    '''Says hello to a user.

    This endpoint leaves Jinja2's autoescaping enabled, so it is safe
    from XSS attacks. Still, you might be able to trick users with some
    clever social engineering. For example, what if you chose a name of
    ``Chris. Your computer has been hacked! Call (555) 555-5555 to
    contact Apple support``?
    '''
    name = request.args.get('name')
    # This template leaves Jinja2's autoescaping enabled.
    return render_template('hello_safe.html', name=name)


@bp.route('/whoami/', methods=('GET', 'POST'))
def whoami():
    '''Simple webform that accepts a user's name.

    Redirects the user to a safe greeting page.
    '''
    return base.whoami(Site.SAFE)


@bp.before_app_request
def load_logged_in_user():
    base.load_logged_in_user()


@bp.route('/register/', methods=('GET', 'POST'))
def register():
    return base.register(Site.SAFE)


@bp.route('/login/', methods=('GET', 'POST'))
def login():
    return base.login(Site.SAFE)


@bp.route('/logout/')
def logout():
    return base.logout(Site.SAFE)


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('safe.login'))

        return view(**kwargs)

    return wrapped_view


@bp.route('/hidden/')
@login_required
def hidden():
    return render_template('hidden_safe.html')
