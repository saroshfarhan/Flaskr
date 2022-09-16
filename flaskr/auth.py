from crypt import methods
import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash
from . import db


bp = Blueprint('auth', __name__, url_prefix='/auth')

'''
This creates a Blueprint named 'auth'. Like the application object, the blueprint needs 
to know where it’s defined, so __name__ is passed as the second argument. 
The url_prefix will be prepended to all the URLs associated with the blueprint.
'''

@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        dab = db.get_db()
        error = None
        if not username:
            error = 'Username is required'
        if not password:
            error = 'Password is required'

        if error is None:
            try:
                dab.execute(
                   "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)), 
                )
                dab.commit()
            except dab.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))
            
        flash(error)

    return render_template('auth/register.html')

'''
For more info on what each method is doing
visit https://flask.palletsprojects.com/en/2.2.x/tutorial/views/
'''

@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        dab = db.get_db()
        error = None
        user = dab.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'
        
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)
    
    return render_template('auth/login.html')


@bp.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')
    dab = db.get_db()
    if user_id is None:
        g.user = None
    else:
        g.user = dab.execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()


@bp.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view


