import io
import secrets
import os
from PIL import Image, ImageOps
from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date, datetime
from functools import wraps
from flask import abort
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_gravatar import Gravatar
from flask_login import LoginManager
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm, UpdateAccountForm,PostForm


ADMINS= [1]
edit = False

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DATABASE_URL")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False, base_url=None)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.get_id() == None:
            return abort(403)
        elif current_user.get_id() not in str(ADMINS):
           return abort(403)
        return f(*args, **kwargs)
    return decorated_function


def save_picture(form_picture):
    random_hex = secrets.token_hex(8)


    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)

    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)

    i.save(picture_path)
    return picture_fn

def save_post(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)

    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/user_posts', picture_fn)
    form_picture.save(picture_path)
    return picture_fn

##CONFIGURE TABLES
class User(db.Model, UserMixin):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')
    password = db.Column(db.String(256), nullable=False)

    posts = relationship('Post', back_populates='author')

db.create_all()

class Post(db.Model):
    __tablename__ = "post"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    author = relationship('User', back_populates='posts')

    title = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    content = db.Column(db.Text, nullable=False)
    user_post = db.Column(db.String(20), nullable=False)


db.create_all()

@app.route("/feeds")
@login_required
def feeds():
    list_name=[]
    all_photos = db.session.query(Post).all()

    for data in all_photos:
        photo = url_for('static', filename='user_posts/' +data.user_post)
        user_name = data.author.username
        profile = url_for('static', filename='profile_pics/' +data.author.image_file)
        content = data.content
        dict = {'photo' : photo,'user_name': user_name, 'profile':profile, 'content':content}
        list_name.append(dict)

    for data in list_name:
        print(data)

    return render_template("feeds.html", authenticated = current_user.is_authenticated, photos = list_name)

@app.route('/search')
@login_required
def search():
    return render_template("search.html", authenticated = current_user.is_authenticated)

@app.route("/profile")
@login_required
def profile():
    all_pts=[]
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    user_pt = Post.query.filter_by(user_id=current_user.id).all()
    # print(user_pt)
    for  posts in user_pt:
        user_posts = url_for('static', filename='user_posts/' + posts.user_post)
        content = posts.content
        dict = {'user_posts': user_posts, 'content': content}
        all_pts.append(dict)
    return render_template("profile.html", authenticated = current_user.is_authenticated, image_file=image_file, photos=all_pts ,current_user=current_user)

#
#
# EDIT AND POST SECTION
#
#

@app.route("/edit",methods=["GET","POST"])
def edit():
    edit = True
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        # current_user.username = form.username.data
        # current_user.email = form.email.data
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template("profile.html", authenticated = current_user.is_authenticated,form=form , edit = edit)

@app.route("/post",methods=["GET","POST"])
def post():

    post = True
    form = PostForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_post(form.picture.data)
        new_post = Post(
            title=form.title.data,
            content=form.content.data,
            user_post=picture_file,
            author= current_user
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for('profile'))
    return render_template("profile.html", authenticated = current_user.is_authenticated,form=form, post=post )


#
#
# LOGIN, REGISTER AND LOGOUT
#
#

@app.route('/register',methods=["GET","POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        user = User.query.filter_by(email=email).first()
        if user:
            flash("User Already exist, please Login")
            return redirect(url_for('login'))
        new_user = User(
            email=form.email.data,
            username=form.name.data,
            password=generate_password_hash(password=form.password.data, salt_length=1,
                                            method='pbkdf2:sha256')
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user,remember=True)
        return redirect(url_for("profile"))
    return render_template("register.html",form=form, authenticated = current_user.is_authenticated)

@app.route('/',methods=["GET","POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    else:
        form = LoginForm()
        if form.validate_on_submit():
            email = form.email.data
            password = form.password.data
            user= User.query.filter_by(email=email).first()
            if not user:
                flash("That email does not exist, please try again")
                return redirect(url_for('register'))
            elif not check_password_hash(user.password, password):
                flash("Worng Password")
                return redirect(url_for('login'))
            else:
                login_user(user,remember=True)
                return redirect(url_for('profile'))
        return render_template("login.html",form=form, authenticated = current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('search'))

if __name__ == "__main__":
    app.run(host='172.20.10.3')