from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError
from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

load_dotenv('mysql.env')
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ["MYSQL_LINK"]
app.config['SECRET_KEY'] = 'TESTING123456789**'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(80), nullable=False)
    password = db.Column(db.String(80), nullable=False)

    def __repr__(self):
        return f'<User {self.name} Email {self.email} Created Successfully!>'


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()], render_kw={"placeholder": "Full Name"})
    email = StringField('Email', validators=[InputRequired(), Email()], render_kw={"placeholder": "Email"})
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8)]
                             , render_kw={"placeholder": "Password"})
    submit = SubmitField('Register')
    def validate_email(self, email):
        existing_user_mail = User.query.filter_by(email=email.data).first()
        if existing_user_mail:
            raise ValidationError('That email already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=8)])
    submit = SubmitField('Login')


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.route('/')
def home():
    return render_template('Home.html')


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():

    return render_template('Dashboard.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Wrong password', 'error')
        else:
            flash('No account found', 'error')
    return render_template('Login.html', form=form)

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data).decode('utf-8')
        new_user = User(name=form.name.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    else:
        flash('There was an error. Please try again.', 'error')
    return render_template('Register.html', form=form)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, port=8080)
