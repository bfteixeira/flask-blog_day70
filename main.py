import os

from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterUserForm, UserLoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps
from os import environ


# CONFIGURE APP, FLASK
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ['SECRET_KEY']
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# SET LOGIN MANAGER
login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

class User(UserMixin,db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False, unique=True)
    password = db.Column(db.String(300), nullable=False, unique=True)
    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    comment = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")

class UserChecker():
    def __init__(self):
        self.id = 0
        self.logged_in = False
        if current_user.is_authenticated:
            self.id = current_user.id
            self.logged_in = True


# USER LOADER (REQUIRED TO KEEP LOGGED USER)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE ADMIN ONLY DECOR
def admin_only(f):
    @wraps(f)
    def decorated_function (*args, **kwargs):
        if current_user.is_authenticated:
            if current_user.id ==1:
                return f(*args, **kwargs)

        return abort(403)
    return decorated_function


# HOMEPAGE ALL BLOG POSTS
@app.route('/')
def get_all_posts():
    posts = db.session.execute(db.select(BlogPost)).scalars().all()
    check_user = UserChecker()
    return render_template("index.html", all_posts=posts, logged_in=check_user.logged_in,user_id=check_user.id)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterUserForm()

    if form.validate_on_submit():
        register_user = db.session.execute(db.select(User).filter_by(email=form.email.data)).scalar()

        if register_user == None:
            password = generate_password_hash(password=form.password.data, method='pbkdf2:sha256', salt_length=8)
            new_user = User(
                name=form.name.data,
                email=form.email.data,
                password=password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('get_all_posts'))

        else:
            flash("You've already signed up that email, log in instead")
            return redirect(url_for('login'))

    else:
        check_user = UserChecker()
        return render_template("register.html", form=form, user_id=check_user.id, logged_in=check_user.logged_in)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = UserLoginForm()

    if form.validate_on_submit():
        user = db.session.execute(db.select(User).filter_by(email=form.email.data)).scalar()

        if user == None:
            flash("User not found. Please try again or register")
            return redirect(url_for('login'))

        elif check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('get_all_posts'))

        else:
            flash("Password incorrect. Please try again")
            return redirect(url_for('login'))
    else:
        check_user = UserChecker()
        return render_template('login.html', form=form, user_id=check_user.id, logged_in=check_user.logged_in)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    requested_post = db.session.execute(db.select(BlogPost).filter_by(id=post_id)).scalar()

    form = CommentForm()

    if form.validate_on_submit():
        new_comment = Comment(comment=form.comment.data, author_id=current_user.id, post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()

    check_user = UserChecker()
    return render_template("post.html", post=requested_post, logged_in=check_user.logged_in, user_id=check_user.id,
                           form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()

    if form.validate_on_submit():

        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )

        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))

    else:
        check_user = UserChecker()
        return render_template("make-post.html", form=form, logged_in=check_user.logged_in, user_id=check_user.id)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = db.session.execute(db.select(BlogPost).filter_by(id=post_id)).scalar()

    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )

    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user.name
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    check_user = UserChecker()
    return render_template("make-post.html", form=edit_form, logged_in=check_user.logged_in, user_id=check_user.id)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.session.execute(db.select(BlogPost).filter_by(post_id)).scalar_one()
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
