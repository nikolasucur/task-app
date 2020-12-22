import enum, os 
from werkzeug.security import generate_password_hash, check_password_hash
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_required, login_user, current_user, logout_user
from flask import Flask, render_template, request, redirect, url_for

basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

app.config['SECRET_KEY'] = 'you will never guess'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir, 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

Migrate(app, db)

class Role(enum.Enum):
    """User role types"""
    employee = 0
    admin = 1

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)

    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))

    login_attempts = db.Column(db.Integer, server_default='0')
    login_success = db.Column(db.Integer, server_default='0')

    employee_identification = db.Column(db.String(128), unique=True, nullable=True)
    role = db.Column(db.Integer, server_default='0')

    def __repr__(self):
        return '<User %r>' % self.email

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    # def is_admin(self):
    #   return self.email in ('sjeremic91@gmail.com','sofkamafin@gmail.com')

    def is_employee(self):
        """check if user has customer role"""
        return self.role == Role.employee.value

    def is_admin(self):
        """check if user has admin role"""
        return self.role == Role.admin.value


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        current_user.email = request.form.get('email')
        current_user.employee_identification = request.form.get('employee_identification')
        db.session.commit()

    return render_template('user.html', user = current_user)

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin():
        return redirect('/')

    users = User.query.all()
    return render_template('admin.html', users=users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        user = User.query.filter(db.func.lower(User.email) == db.func.lower(request.form.get('email'))).first()
        if user:
            user.login_attempts += 1
            db.session.commit()
        if user and user.check_password(request.form.get('password')):
            # login successfull
            user.login_success += 1
            db.session.commit()
            login_user(user)
            return redirect(url_for('index'))


        
        return render_template('login.html', error="Wrong email/password")
    else:
        return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect('/login')
#from flask import Flask,render_template, session


#app = Flask(__name__)
# 
# 
# @app.route('/')
# def index():
#     if 'counter' not in session:
#         session['counter'] = 0
# 
#     session['counter'] += 1
# 
#     return render_template('user.html')
