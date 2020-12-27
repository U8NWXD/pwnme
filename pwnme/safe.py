import functools

from flask import (
    render_template, request, Blueprint, g, redirect, url_for, flash)
from flask_wtf import FlaskForm
from wtforms import IntegerField, StringField, validators

from pwnme import base
from pwnme.base import Site
from pwnme.db import get_db

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


@bp.route('/view-balance/')
@login_required
def view_balance():
    balance = base.get_balance()
    return render_template('view_balance_safe.html', balance=balance)


class WithdrawForm(FlaskForm):
    '''A form for requesting withdrawals.

    Inerits from FlaskForm, so it comes with automatic CSRF protection
    from
    `https://flask-wtf.readthedocs.io/en/stable/quickstart.html#creating-forms
    <Flask-WTF>`_
    '''

    amount = IntegerField('Amount', [validators.DataRequired()])


@bp.route('/withdraw/', methods=('GET', 'POST'))
@login_required
def withdraw():
    form = WithdrawForm()
    if form.validate_on_submit():
        amount = form.amount.data
        balance = base.get_balance()
        new_balance = balance - amount
        base.update_balance(new_balance)
        return redirect(url_for('safe.index'))
    if request.method == 'POST':
        flash(form.errors)
    return render_template('withdraw_safe.html', form=form)


class LookupForm(FlaskForm):

    user = StringField('Username', [validators.DataRequired()])


@bp.route('/lookup_user/', methods=('GET', 'POST'))
@login_required
def lookup_user():
    user_id = None
    form = LookupForm()
    if form.validate_on_submit():
        username = form.user.data
        db = get_db()
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()
        if user_id:
            user_id = int(user['id'])
    elif request.method == 'POST':
        flash(form.errors)
    return render_template(
        'lookup_safe.html', user_id=user_id, form=form)


@bp.after_request
def add_response_headers(response):
    '''Set response headers for security.

    Headers set:

    * ``Strict-Transport-Security``: Once a browser connects to you over
      HTTPS, it will require HTTPS connections for the next 2 years.
      This prevents an attacker from sending users to a fake HTTP
      version of your site. The ``preload`` option will get your site
      included in lists of HTTPS-only sites shipped with major browsers,
      so users will be safe even if they've never visited your site.
    * ``X-Content-Type-Options``: Tell browsers not to sniff responses
      to try and figure out what the content-type is. This sniffing can
      lead to vulnerabilities when the browser and your firewall use a
      different content-type. For example, if XSS code only appears when
      using the content-type sniffed by the browser, the firewall won't
      block the XSS code like it should
    * ``X-Frame-Options``: Prevent someone else from putting your site
      in an iframe. This is important because if someone puts your site
      in an iframe on a malicious site, users visiting the malicious
      site could be tricked into performing actions on your site.
    * ``X-XSS-Protection``: Tell the browser to block any JavaScript
      that is present in both the response and the request. This blocks
      reflected XSS, though it is unnecessary in modern browsers when
      you use a strict content security policy. It's still helpful for
      older browsers, though.
    * ``Content-Security-Policy``: Restrict where the browser can load
      resources for your page. We use a very strict policy here that
      blocks loading all content except styles, which can be loaded from
      our site only. Such a strict policy also blocks nearly all XSS
      attacks. You can check your policy using
      `Google's CSP Evaluator <https://csp-evaluator.withgoogle.com/>`_.

    You can check `Mozilla's documentation
    <https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers>`_ for
    details on these headers and others.`
    '''
    response.headers['Strict-Transport-Security'] = (
        'max-age=63072000; includeSubDomains; preload')
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'none'; style-src 'self'")
    return response
