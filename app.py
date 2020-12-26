from enum import Enum

from flask import Flask, render_template, request, redirect, url_for
app = Flask(__name__)


class Site(Enum):
    SAFE = 'safe'
    VULN = 'vuln'


@app.route('/', methods=('GET',))
def home():
    return render_template('index.html')


@app.route('/vuln/hello/', methods=('GET',))
def hello_vuln():
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


@app.route('/safe/hello/', methods=('GET',))
def hello_safe():
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


def whoami_base(site):
    if request.method == 'POST':
        name = request.form['name']
        dest = 'hello_vuln' if site == Site.VULN else 'hello_safe'
        return redirect(url_for(dest, name=name))
    return render_template('whoami.html')


@app.route('/vuln/whoami/', methods=('GET', 'POST'))
def whoami_vuln():
    '''Simple webform that accepts a user's name.

    Redirects the user to a vulnerable greeting page.
    '''
    return whoami_base(Site.VULN)


@app.route('/safe/whoami/', methods=('GET', 'POST'))
def whoami_safe():
    '''Simple webform that accepts a user's name.

    Redirects the user to a safe greeting page.
    '''
    return whoami_base(Site.SAFE)


def login_base(site):
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
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')


if __name__ == '__main__':
    app.run()
