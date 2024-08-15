from flask import Flask, render_template, send_from_directory, url_for, flash, request, redirect
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_ckeditor import CKEditor
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import uuid
from datetime import datetime
import yaml
import os

from webforms import NamerForm, UserForm, PasswordForm, PostForm, LoginForm, SearchForm


# Create a Flask Instance
app = Flask(__name__)
ckeditor = CKEditor(app)
# Add database
with open('secrets.yaml') as _:
    db_cred = yaml.safe_load(_)
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{db_cred['user']}:{db_cred['password']}@{db_cred['host']}:{db_cred['port']}/{db_cred['dbname']}"

# A key for html files (csrf token kind of)
app.config['SECRET_KEY'] = "a secure key"

# Where to save the files
app.config['UPLOAD_FOLDER'] = 'static/images/'

# Initialize database
db = SQLAlchemy(app)
# To migrate changes in the database
migrate = Migrate(app, db)

# Flask Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


node_modules_path = '/opt/node_modules'

@app.route('/node_modules/<path:filename>')
def node_modules(filename):
    return send_from_directory(node_modules_path, filename)


# User
@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

# Login Page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            # Check the password hash
            if check_password_hash(user.password_hash, form.password.data):
                login_user(user)
                flash('Login Sucessful!!')
                return redirect(url_for('dashboard'))
            else:
                flash('Wrong password - Try again')
        else:
            flash('The user doesnt exist - Try again')

    return render_template('login.html', form=form)

# Dashboard Page
@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

# Logout
@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    flash('You have been logged out')
    return redirect(url_for('login'))

@app.route('/user/add', methods=['GET', 'POST'])
def add_user():
    name = None
    form = UserForm()

    # Validate form
    if form.validate_on_submit():
        user = Users.query.filter_by(email=form.email.data).first()
        if user is None:
            hashed_pw = generate_password_hash(form.password_hash.data, "sha256")
            user = Users(username=form.username.data, name=form.name.data, email=form.email.data, favorite_color=form.favorite_color.data, password_hash=hashed_pw)
            db.session.add(user)
            db.session.commit()
        name = form.name.data
        form.name.data = ''
        form.username.data = ''
        form.email.data = ''
        form.favorite_color.data = ''
        form.password_hash.data = ''

        flash('User added succesfully')

    our_users = Users.query.order_by(Users.date_added)
    return render_template('add_user.html', form=form, name=name, our_users=our_users)


# Udpate database record
@app.route('/update/<int:id>', methods=['GET', 'POST'])
@login_required
def update(id):
    form = UserForm()
    user_to_update = Users.query.get_or_404(id)
    if request.method == 'POST':
        user_to_update.name = request.form['name']
        user_to_update.email = request.form['email']
        user_to_update.favorite_color = request.form['favorite_color']
        user_to_update.about_author = request.form['about_author']
        user_to_update.username = request.form['username']

        # Save the image
        profile_pic = request.files['profile_pic']

        if profile_pic:
            # Grab Image Name
            pic_filename = secure_filename(profile_pic.filename) # Method to make sure it's safe
            # user id + image name to avoid duplicates
            pic_name = "{}_{}".format(user_to_update.id, pic_filename)
            # Save the path to the database (the user field that will then update the database)
            user_to_update.profile_pic = pic_name
            # Now save the image to the path we have designated
            pic_path = os.path.join(app.config['UPLOAD_FOLDER'], pic_name)
            profile_pic.save(pic_path)
            try:
                db.session.commit()
                flash('User Updated Successfully')
                return render_template('update.html', id=user_to_update.id, form=form, user_to_update=user_to_update)
            except:
                flash('Error! Looks like there was a problem')
                return render_template('update.html', form=form, user_to_update=user_to_update)
        else:
            db.session.commit()
            flash('User Updated Successfully')
            return render_template('update.html', id=user_to_update.id, form=form, user_to_update=user_to_update)

    else:
        request.method == 'GET'
        return render_template('update.html', form=form, user_to_update=user_to_update, id=id)

@app.route('/delete/<int:id>')
@login_required
def delete(id):
    if id == current_user.id:
        user_to_delete = Users.query.get_or_404(id)
        name = None
        form = UserForm()

        try:
            db.session.delete(user_to_delete)
            db.session.commit()
            flash('User Deleted Succesfully')
            our_users = Users.query.order_by(Users.date_added)
            return render_template('add_user.html', form=form, name=name, our_users=our_users)
        except:
            flash('Whoops. There was a problem deleting the user')
            our_users = Users.query.order_by(Users.date_added)
            return render_template('add_user.html', form=form, name=name, our_users=our_users)
    else:
        flash('You cannot delete this user')
        return redirect(url_for('dashboard'))


@app.route('/test_pw', methods=['GET', 'POST'])
def test_pw():
    email = None
    password = None
    user_to_check = None
    passed = None
    form = PasswordForm()

    # Validate form
    if form.validate_on_submit():
        email = form.email.data
        password = form.password_hash.data

        # We clear it for the next time around
        form.email.data = ''
        form.password_hash.data = ''

        user_to_check = Users.query.filter_by(email=email).first()

        # Check hashed password
        passed = check_password_hash(user_to_check.password_hash, password)

    return render_template('test_pw.html', email=email, password=password, user_to_check=user_to_check, passed=passed, form=form)

@app.route('/name', methods=['GET', 'POST'])
def name():
    name = None
    form = NamerForm()

    # Validate form
    if form.validate_on_submit():
        name = form.name.data
        form.name.data = '' # We clear it for the next time around
        flash('Form Submitted Successfully')

    return render_template('name.html', name=name, form=form)

# Posts
@app.route('/add-post', methods=['GET', 'POST'])
# @login_required
def add_post():
    form = PostForm()

    if form.validate_on_submit():
        author_id = current_user.id
        post = Posts(title=form.title.data, content=form.content.data, author_id=author_id, slug=form.slug.data)

        # Clear the form
        form.title.data = ''
        form.content.data = ''
        form.author.data = ''
        form.slug.data = ''

        db.session.add(post)
        db.session.commit()
        flash('Post correctly submitted')

    return render_template('add_post.html', form=form)

@app.route('/posts')
def posts():
    posts = Posts.query.order_by(Posts.date_posted)
    return render_template('posts.html', posts=posts)


@app.route('/posts/<int:post_id>')
def post(post_id):
    post = Posts.query.get_or_404(post_id)
    return render_template('post.html', post=post)

@app.route('/posts/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_post(id):
    post = Posts.query.get_or_404(id)
    form = PostForm()

    if form.validate_on_submit():
        post.title = form.title.data
        post.author = form.author.data
        post.slug = form.slug.data
        post.content = form.content.data

        db.session.add(post)
        db.session.commit()
        flash('Post has been updated!')
        return redirect(url_for('post', post_id=post.id))

    if current_user.id == post.author_id:
        form.title.data = post.title
        form.author.data = post.poster.username
        form.slug.data = post.slug
        form.content.data = post.content
        return render_template('edit_post.html', form=form)
    else:
        flash('You are not authorized to edit this post...')
        return redirect(url_for('posts'))


@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    post_to_delete = Posts.query.get_or_404(id)
    id = current_user.id
    # Only if the user is the same as the one who created the post, then let's do the rest
    if id == post_to_delete.poster.id:
        try:
            db.session.delete(post_to_delete)
            db.session.commit()
            flash('Post correctly deleted')
            return redirect(url_for('posts'))
        except:
            flash('Ups! Something went wrong')
            return redirect(url_for('posts'))
    else:
        flash('You must be the post creator to delete it')
        return redirect(url_for('posts'))
        
# Others        
@app.route('/admin')
@login_required
def admin():
    id = current_user.id
    if id == 11:
        return render_template('admin.html')
    else:
        flash('Sorry you are not an admin')
        return redirect(url_for('dashboard'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/user/<name>')
def user(name):
    return render_template('user.html')

# Search function
@app.route('/search', methods=['POST'])
def search():
    form = SearchForm()
    
    if form.validate_on_submit():
        post.searched = form.searched.data
        posts = Posts.query.filter(Posts.content.like(f"%{post.searched}%"))
        posts = posts.order_by(Posts.title).all()

        return render_template('search.html', form=form, searched=post.searched, posts=posts)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500

# Pass Stuff To Navbar
@app.context_processor
def base(): # Cause we are passing this to our base.html file (the one that extends Navbar)
    form = SearchForm()
    return dict(form=form)


# Models
class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    favorite_color = db.Column(db.String(120))
    about_author = db.Column(db.Text(), nullable=True)
    date_added = db.Column(db.DateTime, default=datetime.utcnow())
    profile_pic = db.Column(db.String(), nullable=True) # We are just gonna save the name/path of the image, not the image itself
    # Password
    password_hash = db.Column(db.String(128))
    # A user can have many posts
    posts = db.relationship('Posts', backref='poster') # this one is uppercase because this one DOES refer to the python class

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')
    
    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return '<Name %r>' % self.name


class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow())
    slug = db.Column(db.String(255))
    # Foreign key to link to user
    author_id = db.Column(db.Integer, db.ForeignKey('users.id')) # It's lower case because it's querying the database and not referring to the python class


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)