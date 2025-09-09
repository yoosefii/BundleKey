from flask import Flask, redirect, url_for, render_template, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_required, login_user, logout_user, LoginManager, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, ValidationError, length
from flask_bcrypt import Bcrypt
from datetime import datetime
import json
from flask_migrate import Migrate

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'
bcrypt = Bcrypt(app)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

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
    joined = db.Column(db.DateTime, default=datetime.utcnow)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    poster_username = db.Column(db.String(20), nullable=False)
    poster_id = db.Column(db.Integer)
    content = db.Column(db.String(400), nullable=False)
    published = db.Column(db.DateTime, default=datetime.utcnow)
    likes_json = db.Column(db.String, default='[]')
    dislikes_json = db.Column(db.String, default='[]')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer)
    commenter_username = db.Column(db.String(20), nullable=False)
    commenter_id = db.Column(db.Integer)
    content = db.Column(db.String(200), nullable=False)
    published = db.Column(db.DateTime, default=datetime.utcnow)
    likes_json = db.Column(db.String, default='[]')
    dislikes_json = db.Column(db.String, default='[]')

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer)
    comment_id = db.Column(db.Integer)
    replyer_username = db.Column(db.String(20), nullable=False)
    replyer_id = db.Column(db.Integer)
    content = db.Column(db.String(200), nullable=False)
    published = db.Column(db.DateTime, default=datetime.utcnow)
    likes_json = db.Column(db.String, default='[]')
    dislikes_json = db.Column(db.String, default='[]')

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

def time_ago(time_obj):
    deltatime = datetime.utcnow() - time_obj
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

@app.route('/', methods=['POST', 'GET'])
def home():
    return render_template('home.html', current_user=current_user)

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
            return redirect(url_for('profile', user_id=user.id))

    return render_template('login.html', form = form)

@app.route('/profile', methods=['POST', 'GET'])
@app.route('/profile/<int:user_id>', methods=['POST', 'GET'])
@login_required
def profile(user_id=None):
    if user_id == None:
        user_id = current_user.id
    user = User.query.filter_by(id=user_id).first()
    posts = Post.query.filter_by(poster_id=user_id).all()
    posts_data = [{'object': post,
                   'time_ago': time_ago(post.published),
                   'likes': json.loads(post.likes_json),
                   'dislikes': json.loads(post.dislikes_json)} for post in posts]
    comments = Comment.query.filter_by(commenter_id=user_id).all()
    comments_data = [{'object': comment,
                    #   'post':Post.query.filter_by(id=comment.post_id),
                      'time_ago': time_ago(comment.published),
                      'likes': json.loads(comment.likes_json),
                      'dislikes': json.loads(comment.dislikes_json)} for comment in comments]
    return render_template('profile.html', user=user,
                            joined=time_ago(current_user.joined),
                            posts=posts_data,
                            comments=comments_data)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/feed', methods=['POST', 'GET'])
def feed():
    posts = Post.query.order_by(Post.published).all()
    posts_data = [{'object': post,
                   'time_ago': time_ago(post.published),
                   'likes': json.loads(post.likes_json),
                   'dislikes': json.loads(post.dislikes_json)} for post in posts]
    return render_template('feed.html', posts = posts_data,
                           current_user= current_user)

@app.route('/comments/<int:post_id>', methods=['GET', 'POST'])
def comments_page(post_id):
    post = Post.query.filter_by(id=post_id).first()
    post_data = {'object': post,
                'time_ago': time_ago(post.published),
                'likes': json.loads(post.likes_json),
                'dislikes': json.loads(post.dislikes_json)}
    comments = Comment.query.filter_by(post_id=post_id).all()
    comments_data = [{'object': comment,
                   'time_ago': time_ago(comment.published),
                   'likes': json.loads(comment.likes_json),
                   'dislikes': json.loads(comment.dislikes_json)} for comment in comments]
    return render_template('comments_page.html',post= post_data,
                            comments = comments_data, current_user= current_user)

@app.route('/replies/<int:comment_id>', methods=['GET', 'POST'])
def replies_page(comment_id):
    comment = Comment.query.filter_by(id=comment_id).first()
    post = Post.query.filter_by(id=comment.post_id).first()
    replies = Reply.query.filter_by(comment_id=comment.id)
    post_data = {'object': post,
                'time_ago': time_ago(post.published),
                'likes': json.loads(post.likes_json),
                'dislikes': json.loads(post.dislikes_json)}
    comment_data = {'object': comment,
                   'time_ago': time_ago(comment.published),
                   'likes': json.loads(comment.likes_json),
                   'dislikes': json.loads(comment.dislikes_json)}
    replies_data = [{'object': reply,
                   'time_ago': time_ago(reply.published),
                   'likes': json.loads(reply.likes_json),
                   'dislikes': json.loads(reply.dislikes_json)} for reply in replies]
    return render_template('replies_page.html', post=post_data, comment=comment_data, replies=replies_data)

@app.route('/users')
def users():
    users = User.query.order_by(User.id).all()
    users_data = [{
        'object':user,
        'time_ago':time_ago(user.joined)
    } for user in users]
    return render_template('users.html', users = users_data)

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
    
@app.route('/edit_post/<string:type>/<int:id>', methods=['GET', 'POST'])
@login_required
def edit(type, id):
    if type == 'post':
        obj = Post.query.filter_by(id=id).first()
        target = f'{url_for('feed')}#post-{obj.id}'
    elif type == 'comment':
        obj = Comment.query.filter_by(id=id).first()
        target = f'{url_for('comments_page', post_id=obj.post_id)}#comment-{obj.id}'
    elif type == 'reply':
        obj = Reply.query.filter_by(id=id).first()
        target = f'{url_for('replies_page', comment_id=obj.comment_id)}#reply-{obj.id}'

    if request.method == 'GET':
        return render_template('edit.html', content = obj.content, type=type)
    else:
        new_content = request.form['content']
        obj.content = new_content
        db.session.commit()
        return redirect(target)
    
@app.route('/delete/<string:type>/<int:id>', methods=['GET', 'POST'])
@login_required
def delete(type, id:int):
    obj = []
    if type == 'post':
        obj = Post.query.filter_by(id=id).first()
        underlying_objs_lvl1 = Comment.query.filter_by(post_id=obj.id).all()
        underlying_objs_lvl2 = Reply.query.filter_by(post_id=obj.id).all()
        to_delete = [obj, *underlying_objs_lvl1, *underlying_objs_lvl2]
        target = url_for('feed')
    elif type == 'comment':
        obj = Comment.query.filter_by(id=id).first()
        underlying_objs_lvl1 = Reply.query.filter_by(comment_id=obj.id).all()
        to_delete = [obj, *underlying_objs_lvl1]
        target = f'{url_for('comments_page', post_id = obj.post_id)}'
    elif type == 'reply':
        obj = Reply.query.filter_by(id=id).first()
        to_delete = [obj]
        target = f'{url_for('replies_page', comment_id = obj.comment_id)}'
    for item in to_delete:
        db.session.delete(item)
    db.session.commit()
    return redirect(target)

@app.route('/add_comment/<int:post_id>', methods=['POST', 'GET'])
@login_required
def add_comment(post_id:int):
    content = request.form['content']
    comment = Comment(post_id=post_id,
                      commenter_username=current_user.username,
                      commenter_id=current_user.id,
                      content=content)
    db.session.add(comment)
    db.session.commit()
    return redirect(url_for('comments_page', post_id=post_id))

@app.route('/add_reply/<int:comment_id>/<int:post_id>', methods=['POST', 'GET'])
@login_required
def add_reply(comment_id:int, post_id:int):
    content = request.form['content']
    reply = Reply(post_id=post_id,
                  comment_id=comment_id,
                  replyer_username=current_user.username,
                  replyer_id=current_user.id,
                  content=content)
    db.session.add(reply)
    db.session.commit()
    return redirect(url_for('replies_page', comment_id=comment_id))


@app.route('/vote/<string:parent_type>/<int:parent_id>', methods=['POST', 'GET'])
@login_required
def vote(parent_type:str, parent_id:int):
    if parent_type == 'post':
        parent = Post.query.filter_by(id=parent_id).first()
        target = f"{request.referrer}#post-{parent_id}"
    elif parent_type == 'comment':
        parent = Comment.query.filter_by(id=parent_id).first()
        target = f'{request.referrer}#comment-{parent_id}'
    elif parent_type == 'reply':
        parent = Reply.query.filter_by(id=parent_id).first()
        target = f'{request.referrer}#reply-{parent_id}'
    vote = request.form.get('vote')
    likes = json.loads(parent.likes_json)
    dislikes = json.loads(parent.dislikes_json)
    if vote == 'like':
        if current_user.id in likes:
            likes.remove(current_user.id)
        else:
            if current_user.id in dislikes:
                dislikes.remove(current_user.id)
            likes.append(current_user.id)
        parent.dislikes_json = json.dumps(dislikes)
        parent.likes_json = json.dumps(likes)
    elif vote == 'dislike':
        if current_user.id in dislikes:
            dislikes.remove(current_user.id)
        else:
            if current_user.id in likes:
                likes.remove(current_user.id)
            dislikes.append(current_user.id)
        parent.likes_json = json.dumps(likes)
        parent.dislikes_json = json.dumps(dislikes)
    db.session.commit()
    
    return redirect(target)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)