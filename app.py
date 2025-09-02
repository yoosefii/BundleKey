from flask import Flask, redirect, url_for, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, login_user, logout_user, LoginManager, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, ValidationError, length
from flask_bcrypt import Bcrypt
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
bcrypt = Bcrypt(app)

db = SQLAlchemy(app)

the_login_manager = LoginManager()
the_login_manager.init_app(app)
the_login_manager.login_view = 'login'

@the_login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=int(user_id)).first()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poster_username = db.Column(db.String(20), nullable=False)
    poster_id = db.Column(db.Integer)
    content = db.Column(db.String(200), nullable=False)
    published = db.Column(db.DateTime, default=datetime.utcnow)



class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(), length(min=4, max=12)],
                           render_kw={'placeholder': 'username'})
    password = PasswordField(validators=[InputRequired(), length(min=8, max=20)],
                           render_kw={'placeholder': 'password'})
    submit = SubmitField()

    def validate_username(self, username):
        existing_username = User.query.filter_by(username= username.data).first()
        if existing_username :
            raise ValidationError('username already existing, please choose another one!')



class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(), length(min=4, max=12)],
                           render_kw={'placeholder': 'username'})
    password = PasswordField(validators=[InputRequired(), length(min=8, max=20)],
                           render_kw={'placeholder': 'password'})
    submit = SubmitField()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['POST', 'GET'])
def register():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        user = User(username=form.username.data, password= hashed_password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template('register.html', form = form)

@app.route('/login', methods=['POST', 'GET'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))

    return render_template('login.html', form = form)

@app.route('/dashboard', methods=['POST', 'GET'])
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/feed', methods=['POST', 'GET'])
def feed():
    posts = Post.query.order_by(Post.published).all()
    def time_ago(post):
        deltatime = datetime.utcnow() - post.published
        seconds = deltatime.total_seconds()
        intervals = (
        ('year', 31557600),
        ('month', 2629800),
        ('week', 604800),
        ('day', 86400),
        ('hour', 3600),
        ('minute', 60),
        ('second', 1),
        )
        for name, length in intervals:
            value = int(seconds // length)
            if value: return f'{value} {name}{'s' if value>1 else''} ago'
        return 'just now'
    posts = (
        (post, time_ago(post)) for post in posts
    )
    return render_template('feed.html', posts = posts, current_user= current_user)

@app.route('/post', methods=['POST', 'GET'])
@login_required
def post():
    if request.method == 'GET':
        return render_template('post.html')
    else:
        content = request.form['content']
        post = Post(poster_id=current_user.id,
                    poster_username=current_user.username,
                    content=content)
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('feed'))
    
@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def edit_post(post_id):
    post = Post.query.filter_by(id=post_id).first()
    if request.method == 'GET':
        return render_template('edit.html', content = post.content)
    else:
        new_content = request.form['content']
        post.content = new_content
        db.session.commit()
        return redirect(url_for('feed'))
    
@app.route('/delete_post/<int:post_id>', methods=['GET', 'POST'])
@login_required
def delete_post(post_id:int):
    post = Post.query.filter_by(id=post_id).first()
    db.session.delete(post)
    db.session.commit()
    return redirect(url_for('feed'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)