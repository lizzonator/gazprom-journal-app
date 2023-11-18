from flask import Flask, render_template, redirect, url_for, request, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, SelectField, FileField
from wtforms.validators import DataRequired
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # You can replace this with your actual database URL
app.config['UPLOAD_FOLDER'] = 'uploads'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'


# Database model for User
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(100), nullable=False)


# Database model for LogEntry
class LogEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(20), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('log_entries', lazy=True))
    file = db.Column(db.String(255))  # Adjust the length as needed


# WTForms for creating log entries
class LogEntryForm(FlaskForm):
    type = SelectField('Type', choices=[('команда', 'Команда'), ('сообщение', 'Сообщение'), ('инцидент', 'Инцидент'), ('принятие смены', 'Принятие смены')], validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    file = FileField('Attach File')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Login failed. Check your username and password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    log_entries = LogEntry.query.order_by(LogEntry.timestamp.desc()).all()
    return render_template('index.html', log_entries=log_entries)


@app.route('/create', methods=['GET', 'POST'])
@login_required
def create():
    form = LogEntryForm()

    if form.validate_on_submit():
        type = form.type.data
        content = form.content.data
        file = form.file.data

        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        else:
            filename = None

        new_log_entry = LogEntry(type=type, content=content, user=current_user, file=filename)
        db.session.add(new_log_entry)
        db.session.commit()

        flash('Log entry created successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('create.html', form=form)


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(id):
    log_entry = LogEntry.query.get_or_404(id)
    form = LogEntryForm(obj=log_entry)

    if form.validate_on_submit():
        log_entry.type = form.type.data
        log_entry.content = form.content.data
        file = form.file.data

        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            log_entry.file = filename

        db.session.commit()
        flash('Log entry updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit.html', form=form, log_entry=log_entry)


@app.route('/delete/<int:id>')
@login_required
def delete(id):
    log_entry = LogEntry.query.get_or_404(id)
    db.session.delete(log_entry)
    db.session.commit()
    flash('Log entry deleted successfully!', 'success')
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        # Add example users (replace these with your actual user data)
        example_users = [
            {'username': 'boss', 'password': 'zhopa'},
            {'username': 'senior_engineer', 'password': 'zh0p4'},
            {'username': 'junior_engineer', 'password': 'ZHOPA'},
            # Add more users as needed
        ]

        for user_data in example_users:
            username = user_data['username']

            # Check if the user already exists
            existing_user = User.query.filter_by(username=username).first()

            if not existing_user:
                password = generate_password_hash(user_data['password'])
                new_user = User(username=username, password_hash=password)
                db.session.add(new_user)
            
            print(f"Adding user: {user_data['username']}")

        # Commit the changes to the database
        db.session.commit()

    app.run(debug=True)
