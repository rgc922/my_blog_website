#### relationship databases
#### https://docs.sqlalchemy.org/en/13/orm/basic_relationships.html



from flask import Flask, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar

### los que yo puse
from datetime import date
# from sqlalchemy import ForeignKey


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


### login start
login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.filter_by(id=user_id).first()


#### CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(200), unique=True)
    password = db.Column(db.String(200))
    name = db.Column(db.String(200))

    ### relacion con la otra DB
    posts = relationship('BlogPost', back_populates="author")
    comments = relationship('Comment', back_populates="comment_author")

### 
# db.create_all()
# db.create_all(bind=User)

### 

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

    ### relacion con la otra database
    ### create Foreign key, "users.id" the users refers to the tablename User
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    #### Create reference to the User Object, the "posts" refers to the posts property
    #### in the User class
    author = relationship("User", back_populates="posts")

    comments = relationship("Comment", back_populates="parent_post")


class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
        
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"))
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    parent_post = relationship("BlogPost", back_populates="comments")
    comment_author = relationship("User", back_populates="comments")

    text = db.Column(db.Text, nullable=False)

### solo la primera vez para arrancar la tabla
### con el with app context ya  sepuede dejar, crea la tabla que le faltaba
with app.app_context():
    db.create_all()





##### create admin-only decorator
from functools import wraps
from flask import abort

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ## if id not 1 then return abort with 403 error
        if current_user.get_id() != '1':
            return abort(403)
        ### otherwise continue with the function
        return f(*args, **kwargs)
    return decorated_function




@app.route('/')
def get_all_posts():
    # posts = BlogPost.query.all()   ## function deprecated
    posts = db.session.execute(db.select(BlogPost)).scalars().all()
    # print(current_user)
    # print(type(current_user.get_id()))
    return render_template("index.html", all_posts=posts, current_user=current_user)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form_new_user = RegisterForm()

    # print(form_new_user.validate_on_submit())
    if form_new_user.validate_on_submit():


        email = form_new_user.email.data
        name = form_new_user.name.data
        password = form_new_user.password.data
        # print(email, name)

        email_check = User.query.filter_by(email=email).first()

        ### si el correo ya existe, lo mando a la pàgina de login.
        if email_check:
            flash("You've already signed up with that email, log in instead !!")
            return redirect(url_for('login'))
        
        ###
        ### como el correo no estaba en DB, procedo a crearlo
        hash_and_salted_password = generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )

        ###
        new_user = User(
            name = name,
            email = email,
            password = hash_and_salted_password
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)  ### dejar al usuario loggeado
            return redirect(url_for('get_all_posts'))
        except Exception as e:
            print(e)
            return redirect(url_for('get_all_posts'))

        
    return render_template("register.html", form=form_new_user, current_user=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form_login = LoginForm()
    if form_login.validate_on_submit():
        email = form_login.email.data
        password = form_login.password.data

        ### check email 
        user = User.query.filter_by(email=email).first()

        if not user:
            flash("That email does not exist. Please try again.")
        elif not check_password_hash(user.password, password):
            flash("Password incorrect, please try again.")
        else:
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", form=form_login, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['GET', 'POST'])
def show_post(post_id):
    # requested_post = BlogPost.query.get(post_id)  ### legacy function
    requested_post = db.get_or_404(BlogPost, post_id)


    comment_form = CommentForm()

    comments_list = db.session.execute(db.select(Comment).filter_by(post_id=post_id)).scalars().all()

    if comment_form.validate_on_submit():
        if current_user.is_authenticated:  

            requested_post = db.get_or_404(BlogPost, post_id)

            new_comment = Comment(         

                comment_author = current_user,
                text = comment_form.comment_text.data,
                parent_post = requested_post,
                )

            try:
                db.session.add(new_comment)
                db.session.commit()
                return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form, comments=comments_list)
            except Exception as e:
                print(e)
                return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form, comments=comments_list)



    return render_template("post.html", post=requested_post, current_user=current_user, form=comment_form, comments=comments_list)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
# @admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        # print(type(current_user.get_id()))
        # user_db = db.get_or_404(User, current_user.get_id())
        # print(user_db.name)
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id=current_user.get_id(),
            date=date.today().strftime("%B %d, %Y"),
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['GET', 'POST'])
@admin_only
def edit_post(post_id):
    # post = BlogPost.query.get(post_id)  ## legacy function
    post = db.get_or_404(BlogPost, post_id)

    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        # author=post.user_db.name,
        body=post.body
    )
    if edit_form.validate_on_submit():
        # user_db = db.get_or_404(User, current_user.get_id())
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author_id = current_user.get_id()
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    # post_to_delete = BlogPost.query.get(post_id)   ### legacy function
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, use_reloader=False, debug=True)
