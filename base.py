import os

from flask_wtf import FlaskForm
from werkzeug.utils import redirect
from wtforms import PasswordField, BooleanField, SubmitField
from wtforms.fields.html5 import EmailField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash
from data import db_session
from data.users import User, RegisterForm
from flask import Flask, render_template, request, make_response
from flask_login import LoginManager, login_user, login_required, logout_user

app = Flask(__name__)
app.config['SECRET_KEY'] = 'yandexlyceum_secret_key'

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    db_sess = db_session.create_session()
    return db_sess.query(User).get(user_id)


class LoginForm(FlaskForm):
    email = EmailField('Почта', validators=[DataRequired()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    remember_me = BooleanField('Запомнить меня')
    submit = SubmitField('Войти')


@app.route('/snow/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        db_sess = db_session.create_session()
        user = db_sess.query(User).filter(User.email == form.email.data).first()
        print(user.check_password(form.password.data), form.password.data)
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            cookie_saver(user.email, user.hashed_password)
            return redirect("/snow/main")
        return render_template('login.html',
                               message="Неправильный логин или пароль",
                               form=form)
    return render_template('login.html', title='Авторизация', form=form)


def cookie_saver(email, password):
    res = make_response()
    res.set_cookie(email, password)
    return res


@app.route("/snow/<name>")
def index(name):
    pics = []
    for i in os.listdir("static/img/pics/"):
        pics.append("/static/img/pics/" + i)
    try:
        return render_template(name + ".html", title="Snow", pics=pics)
    except:
        return render_template("error_in_url.html", title="Snow")


@app.route('/snow/register', methods=['GET', 'POST'])
def reqister():
    form = RegisterForm()
    if form.validate_on_submit():
        if form.password.data != form.password_again.data:
            return render_template('register.html', title='Snow',
                                   form=form,
                                   message="Пароли не совпадают")
        db_sess = db_session.create_session()
        if db_sess.query(User).filter(User.email == form.email.data).first():
            return render_template('register.html', title='Snow',
                                   form=form,
                                   message="Такой пользователь уже есть")
        user = User()
        user.email = form.email.data
        user.hashed_password = generate_password_hash(form.password.data)
        user.rank = "client"
        db_sess.add(user)
        db_sess.commit()
        cookie_saver(user.email, user.hashed_password)
        return redirect('/snow/login')
    return render_template('register.html', title='Snow', form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect("/snow/main")


@app.route("/")
@app.route("/<some>")
def index_err(some):
    return render_template("error_in_url.html", title="Snow")


def main():
    db_session.global_init("db/users.db")
    app.run(port=8080, host='127.0.0.1')


if __name__ == '__main__':
    main()
