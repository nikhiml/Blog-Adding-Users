from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from sqlalchemy import ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, NewUserForm, CurrentUserForm, CommentsForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# Initialize Gravatar with Flask app to be able to use the avatar images for the commenter
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)

##CONFIGURE TABLES

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    user_posts = db.relationship("BlogPost", back_populates="author")
    user_comments = db.relationship("Comment", back_populates="author")


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = db.relationship("User", back_populates="user_posts")
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    blog_comments = db.relationship("Comment", back_populates="blog")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    author = db.relationship("User", back_populates="user_comments")
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    blog = db.relationship("BlogPost", back_populates="blog_comments")
    blog_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))


db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
        return abort(403)
    decorated_function.__name__ = f.__name__
    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    new_user_form = NewUserForm()
    current_user_form = CurrentUserForm()
    if new_user_form.validate_on_submit():
        existing_user = User.query.filter_by(email=new_user_form.email.data).first()
        if existing_user is not None:
            flash("Email Already Exists, Please Log In")
            return redirect(url_for('login', form=current_user_form))
        new_user = User()
        new_user.email = new_user_form.email.data
        new_user.name= new_user_form.name.data
        new_user.password = generate_password_hash(new_user_form.password.data, method='pbkdf2:sha256', salt_length=8)
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
        # return redirect(url_for('login', form=current_user_form))
    return render_template("register.html", form=new_user_form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    current_user_form = CurrentUserForm()
    if current_user_form.validate_on_submit():
        check_user = User.query.filter_by(email=current_user_form.email.data).first()
        if check_user:
            if check_password_hash(check_user.password, current_user_form.password.data):
                login_user(check_user)
                return redirect(url_for('get_all_posts'))

            else:
                flash("Invalid Password")

        else:
            flash("Invalid Email Id")

    return render_template("login.html", form=current_user_form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    form=CommentsForm()
    requested_post = BlogPost.query.get(post_id)
    if form.validate_on_submit():
        if current_user and current_user.is_authenticated:
            new_comment = Comment()
            new_comment.text = form.body.data
            new_comment.author_id = current_user.id
            new_comment.blog_id = post_id
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash('Please login to comment')
            return redirect(url_for('login'))
    return render_template("post.html", post=requested_post, form=form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@login_required
@admin_required
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_required
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        # post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>", methods=['GET', 'POST'])
@login_required
@admin_required
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5001)
