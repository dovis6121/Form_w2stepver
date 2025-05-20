from flask import Flask, render_template, redirect, url_for, flash, session, send_from_directory, request
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, DateField, TelField
from wtforms.validators import DataRequired, Length, ValidationError, Email, Optional
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import os
from datetime import timedelta, datetime

app = Flask(__name__)

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    
    registration_complete = db.Column(db.Boolean, default=False)
    
    full_name = db.Column(db.String(100), nullable=True)
    date_of_birth = db.Column(db.Date, nullable=True)
    phone = db.Column(db.String(20), nullable=True)
    address = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f'<User {self.username}>'

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=80, message="Username must be between 4 and 80 characters")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=80, message="Username must be between 4 and 80 characters")
    ])
    email = StringField('Email', validators=[
        DataRequired(),
        Email(message="Please enter a valid email address")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=8, message="Password must be at least 8 characters long")
    ])
    submit = SubmitField('Continue to Step 2')
    
    def validate_username(self, username):
        existing_user = User.query.filter_by(username=username.data).first()
        if existing_user:
            raise ValidationError('Username already exists. Please choose a different one.')
    
    def validate_email(self, email):
        existing_user = User.query.filter_by(email=email.data).first()
        if existing_user:
            raise ValidationError('Email already registered. Please use a different one.')

class ProfileForm(FlaskForm):
    full_name = StringField('Full Name', validators=[
        DataRequired(),
        Length(min=2, max=100, message="Name must be between 2 and 100 characters")
    ])
    date_of_birth = DateField('Date of Birth (YYYY-MM-DD)', format='%Y-%m-%d', validators=[
        DataRequired(message="Please enter a valid date in format YYYY-MM-DD")
    ])
    phone = TelField('Phone Number', validators=[
        DataRequired(),
        Length(min=10, max=20, message="Please enter a valid phone number")
    ])
    address = StringField('Address', validators=[
        Optional(),
        Length(max=200)
    ])
    submit = SubmitField('Complete Registration')

@app.route('/')
def home():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            if not user.registration_complete:
                flash('Please complete your profile registration first.', 'warning')
                session['temp_user_id'] = user.id
                return redirect(url_for('register_step2'))
                
            session['user_id'] = user.id
            session.permanent = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login unsuccessful. Please check username and password', 'danger')
    
    return render_template('login.html', form=form, title='Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        
        new_user = User(
            username=form.username.data, 
            email=form.email.data,
            password=hashed_password,
            registration_complete=False
        )
        db.session.add(new_user)
        db.session.commit()
        
        session['temp_user_id'] = new_user.id
        
        flash('Account created! Please complete your profile information.', 'success')
        return redirect(url_for('register_step2'))
    
    return render_template('register.html', form=form, title='Register - Step 1')

@app.route('/register/step2', methods=['GET', 'POST'])
def register_step2():
    if 'temp_user_id' not in session:
        flash('Please complete the first registration step', 'warning')
        return redirect(url_for('register'))
    
    user = User.query.get_or_404(session['temp_user_id'])
    
    form = ProfileForm()
    if form.validate_on_submit():
        user.full_name = form.full_name.data
        user.date_of_birth = form.date_of_birth.data
        user.phone = form.phone.data
        user.address = form.address.data
        user.registration_complete = True
        
        db.session.commit()
        
        session.pop('temp_user_id', None)
        
        session['user_id'] = user.id
        session.permanent = True
        
        flash('Registration complete. Welcome!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('register_step2.html', form=form, title='Register - Step 2')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in first', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get_or_404(session['user_id'])
    
    if not user.registration_complete:
        flash('Please complete your profile first', 'warning')
        session['temp_user_id'] = user.id
        return redirect(url_for('register_step2'))
    
    return render_template('dashboard.html', title='Dashboard', user=user)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    app.run(debug=True)