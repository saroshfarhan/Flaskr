from crypt import methods
import functools
from operator import methodcaller

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)

from werkzeug.security import check_password_hash, generate_password_hash
import db


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
        db.get_db()

        if not username:
            error = 'Username is required'
        if not password:
            error = 'Password is required'

        if error is None:
            try:
                db.execute(
                   "INSERT INTO user (username, password) VALUES (?, ?)",
                    (username, generate_password_hash(password)), 
                )
            except db.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))
            
        flash(error)

    return render_template('auth/register.html')

'''
For more info on what each method is doing
visit https://flask.palletsprojects.com/en/2.2.x/tutorial/views/
'''

