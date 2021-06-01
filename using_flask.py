import os
from flask import Flask
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, FileField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_login import UserMixin
from flask import render_template, url_for, flash, redirect, request, abort
from flask_login import login_user, current_user, logout_user, login_required
from sqlalchemy import func


app = Flask(__name__)
app.secret_key = "Secret Key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:''@localhost/post_website'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'


class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError(
                'That username is taken. Please choose a different one.')
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError(
                'That email is taken. Please choose a different one.')


class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')


class UpdateAccountForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = StringField('Change Password')
    image_file = FileField('Select Profile')
    submit = SubmitField('Update')
    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError(
                    'That username is taken. Please choose a different one.')
    def validate_email(self, email):
        if email.data != current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError(
                    'That email is taken. Please choose a different one.')


class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    Category = StringField('Select Category', validators=[DataRequired()])
    image = FileField('Select Image', validators=[FileAllowed(['png', 'jpg', 'jpeg'], 'Images only!') ])
    submit = SubmitField('Post')


class PasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    new_confirm_password = PasswordField('New Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Change')


class CommentForm(FlaskForm):
    comment = TextAreaField('Comment', validators=[DataRequired()])
    submit = SubmitField('Post')


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    image_file = db.Column(db.String(32767), nullable=False, default='default_user.jpg') 
    register_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    last_seen = db.Column(db.DateTime, nullable=False, default=datetime.now)
    posts = db.relationship('Post', backref='author', lazy=True)
    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.password}', '{self.image_file}', '{self.register_date}', '{self.last_seen}')"


class Post(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(32767), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.now)
    content = db.Column(db.Text, nullable=False)
    Category = db.Column(db.String(32767), nullable=False)
    image = db.Column(db.String(32767)) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment = db.relationship('Comment', backref='post_comment', lazy=True)
    def __repr__(self):
        return f"Post('{self.title}', '{self.date_posted}', '{self.Category}', '{self.image}')"


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    postid = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    userid = db.Column(db.Integer, db.ForeignKey('user.username'), nullable=False)
    comment = db.Column(db.Text, nullable=False)
    comment_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    def __repr__(self):
        return f"Post('{self.comment}', '{self.comment_date}')"


class Friends(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_sender = db.Column(db.Integer, nullable=False)
    sentto = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(10), nullable=False, default='0')
    request_sent_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    def __repr__(self):
        return f"Friends('{self.request_sent_date}')"


class Reaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    postid = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    reaction = db.Column(db.String(1), nullable=False, default='0')
    reaction_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    btn_color = db.Column(db.String(20), nullable=False)
    def __repr__(self):
        return f"Friends('{self.reaction_date}')"


class Favourite(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    add_date = db.Column(db.DateTime, nullable=False, default=datetime.now)
    def __repr__(self):
        return f"Friends('{self.post_id}', '{self.user_id}', '{self.add_date}')"


@app.route('/', defaults={"page_num": 1})
@app.route("/<int:page_num>")
def home(page_num=1):
    comt_count = db.session.query(Post.id, func.count(Comment.postid)).join(Comment).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    like_count = db.session.query(Post.id, func.count(Reaction.reaction), Reaction.user_id, Reaction.btn_color).filter(Reaction.reaction=='1').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    dislike_count = db.session.query(Post.id, func.count(Reaction.reaction), Reaction.user_id, Reaction.btn_color).filter(Reaction.reaction=='2').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    posts = Post.query.order_by(Post.date_posted.desc()).paginate(per_page=5, page=page_num)
    like_exists=db.session.query(Post.id, Reaction.user_id, Reaction.btn_color).filter(Reaction.reaction=='1').join(Reaction).all()
    dislike_exists=db.session.query(Post.id, Reaction.user_id, Reaction.btn_color).filter(Reaction.reaction=='2').join(Reaction).all()
    favourite_exists=db.session.query(Favourite.post_id, Favourite.user_id).all()
    return render_template('main.html', posts=posts, comt_count=comt_count, like_count=like_count, dislike_count=dislike_count, like_exists=like_exists, dislike_exists=dislike_exists, favourite_exists=favourite_exists)


@app.route('/liked_post', defaults={"page_num": 1})
@app.route("/liked_post<int:page_num>")
@login_required
def liked_post(page_num=1):
    comt_count = db.session.query(Post.id, func.count(Comment.postid)).join(Comment).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    like_count = db.session.query(Post.id, func.count(Reaction.reaction)).filter(Reaction.reaction=='1').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    dislike_count = db.session.query(Post.id, func.count(Reaction.reaction)).filter(Reaction.reaction=='2').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    liked_post=db.session.query(User, User.id, User.username, User.image_file,Post.id, Post.title, Post.content, Post.date_posted, Post.user_id, Post.image).join(Post, Reaction).filter(Reaction.user_id==current_user.id, Reaction.reaction=="1").order_by(Post.date_posted.desc()).paginate(
        per_page=5, page=page_num)
    return render_template('like_post_show.html', liked_post=liked_post, comt_count=comt_count, like_count=like_count, dislike_count=dislike_count)


UPLOAD_FOLDER = 'C:/Users/Ram Sharma/Desktop/python/static/profile_img/'
ALLOWED_EXTENSIONS = set(['png', 'jpg', 'jpeg'])
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
@app.route("/register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register_form.html', title='Register', form=form)


@app.route("/login", methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            user.last_seen = datetime.now()
            db.session.commit()
            flash('Welcome ' + user.username, 'success')
            return redirect(next_page) if next_page else redirect(url_for('home'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login_form.html', title='Login', form=form)


@app.route("/logout")
def logout():
    logout_user()
    flash('Logout successfully!', 'success')
    return redirect(url_for('home'))


@app.route("/post/new", methods=['GET', 'POST'])
@login_required
def new_post():
    form = PostForm()
    if form.validate_on_submit():
        if request.method == 'POST':
            image = request.files['image']
            if image and allowed_file(image.filename):
                filename = image.filename
                post = Post(title=form.title.data, content=form.content.data, author=current_user, Category=form.Category.data, image=filename)
                image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                db.session.add(post)
                db.session.commit()
                flash('Your post has been created!', 'success')
                return redirect(url_for('home'))
            else:
                post = Post(title=form.title.data, content=form.content.data, author=current_user, Category=form.Category.data)
                db.session.add(post)
                db.session.commit()
                flash('Your post has been created!', 'success')
                return redirect(url_for('home'))
    return render_template('add_post.html', title='New Post', form=form, legend='New Post')


@app.route("/post/<id>/update", methods=['GET', 'POST'])
@login_required
def update_post(id):
    post = Post.query.get_or_404(id)
    if post.author != current_user:
        abort(403)
    if post.author == current_user:
        form = PostForm()
        if form.validate_on_submit():
            post.title = form.title.data
            post.content = form.content.data
            post.Category = form.Category.data
            if request.method == 'POST':
                image = request.files['image']
                if image and allowed_file(image.filename):
                    filename = image.filename
                    image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    post.image = filename
            db.session.commit()
            flash('Your post has been updated!', 'success')
            return redirect(url_for('home'))
        elif request.method == 'GET':
            form.title.data = post.title
            form.content.data = post.content
            form.Category.data = post.Category
            form.image.data = post.image
            return render_template('add_post.html', title='Update Post',
                                   form=form, legend='Update Post')
        return redirect(url_for('home'))


@app.route('/delete/<id>/', methods=['GET', 'POST'])
@login_required
def delete(id):
    post = Post.query.get_or_404(id)
    if post.author == current_user:
        my_data = Post.query.get(id)
        db.session.delete(my_data)
        db.session.commit()
        flash('Your post has been deleted!', 'success')
    return redirect(url_for('home'))


@app.route("/post/<post_id>")
def post(post_id):
    form = CommentForm()
    posts = Post.query.get_or_404(post_id)
    file_img = '/profile_img/'+posts.image
    profile_img = '/profile_img/'+posts.author.image_file
    comt = Comment.query.filter(Comment.postid == posts.id).order_by(Comment.comment_date.desc())
    post_category = Post.query.filter(Post.Category==posts.Category).order_by(Post.date_posted.desc())[:5]
    dups = db.session.query(Post.id, Post.title, Post.content, Post.date_posted, func.count(Comment.postid)).join(Post).filter(Post.Category==posts.Category).group_by(Comment.postid).order_by(func.count(Comment.postid).desc())[:5]
    return render_template('single_post.html', posts=posts, post_category=post_category, form=form, comt=comt, dups=dups, file_img=file_img, profile_img=profile_img)


@app.route("/user_post", defaults={"page_num": 1})
@app.route("/user_post<int:page_num>", methods=['GET', 'POST'])
@login_required
def user_post(page_num=1):
    posts = Post.query.filter(Post.author == current_user).order_by(
        Post.date_posted.desc()).paginate(per_page=5, page=page_num)
    return render_template('user_post.html', posts=posts)


@app.route('/science', defaults={"page_num": 1})
@app.route("/science<int:page_num>")
def science(page_num=1):
    comt_count = db.session.query(Post.id, func.count(Comment.postid)).join(Comment).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    like_count = db.session.query(Post.id, func.count(Reaction.reaction)).filter(Reaction.reaction=='1').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    dislike_count = db.session.query(Post.id, func.count(Reaction.reaction)).filter(Reaction.reaction=='2').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    posts = Post.query.filter(Post.Category == 'Science').order_by(
        Post.date_posted.desc()).paginate(per_page=5, page=page_num)
    like_exists=db.session.query(Post.id, Reaction.user_id, Reaction.btn_color).filter(Reaction.reaction=='1').join(Reaction).all()
    dislike_exists=db.session.query(Post.id, Reaction.user_id, Reaction.btn_color).filter(Reaction.reaction=='2').join(Reaction).all()
    favourite_exists=db.session.query(Favourite.post_id, Favourite.user_id).all()
    return render_template('science.html', posts=posts, comt_count=comt_count, like_count=like_count, dislike_count=dislike_count, like_exists=like_exists, dislike_exists=dislike_exists, favourite_exists=favourite_exists)


@app.route("/profile/writer/post<int:post_id>/", methods=['GET', 'POST'])
def writer_profile(post_id):
    post = Post.query.filter(Post.id==post_id).first()
    posts = Post.query.filter(Post.user_id == post.author.id).order_by(Post.date_posted.desc())[:1]
    total_post = Post.query.filter(Post.author==post.author).count()
    filename = '/profile_img/'+post.author.image_file
    post_img = '/profile_img/'+posts[0].image
    if post.author == current_user:
        return redirect(url_for('user_profile'))
    else:
        return render_template('profile_writer.html', total_post=total_post, post_writer=post.author, filename=filename, posts=posts, post_img=post_img)


@app.route("/search", methods=['GET','POST'])
def search():
    comt_count = db.session.query(Post.id, func.count(Comment.postid)).join(Comment).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    like_count = db.session.query(Post.id, func.count(Reaction.reaction)).filter(Reaction.reaction=='1').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    dislike_count = db.session.query(Post.id, func.count(Reaction.reaction)).filter(Reaction.reaction=='2').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    if request.method == 'POST':
        form = request.form
        search_value=form['search_string']
        search = "%{}%".format(search_value)
        results = Post.query.filter(Post.title.like(search) | Post.content.like(search)).order_by(
        Post.date_posted.desc()).all()
        return render_template("search_data.html", posts=results, comt_count=comt_count, like_count=like_count, dislike_count=dislike_count)


@app.route('/user_profile', defaults={"page_num": 1})
@app.route("/user_profile<int:page_num>", methods=['GET', 'POST'])
@login_required
def user_profile(page_num=1):
    total_post = Post.query.filter(Post.user_id==current_user.id).count()
    filename = 'static/profile_img/'+current_user.image_file
    posts = Post.query.filter(Post.author == current_user).order_by(
        Post.date_posted.desc()).paginate(per_page=5, page=page_num)
    f=Friends.query.filter(Friends.sentto==current_user.id, Friends.status=='0').count()
    return render_template('profile.html', filename=filename, total_post=total_post, posts=posts, f=f)


@app.route("/user_profile_update", methods=['GET', 'POST'])
@login_required
def user_profile_update():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.email = form.email.data
        if request.method == 'POST':
            image_file = request.files['image_file']
            if image_file and allowed_file(image_file.filename):
                filename = image_file.filename
                image_file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.image_file = filename
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('user_profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.image_file.data = current_user.image_file
    return render_template('update_profile.html', form=form)


@app.route("/profile/user_id/post<int:user_id>/", methods=['GET', 'POST'])
def user_id_profile(user_id):
    post = Post.query.filter(Post.user_id==user_id).first()
    posts = Post.query.filter(Post.user_id == post.author.id).order_by(Post.date_posted.desc())[:1]
    total_post = Post.query.filter(Post.author==post.author).count()
    filename = '/profile_img/'+post.author.image_file
    if post.author == current_user:
        return redirect(url_for('user_profile'))
    else:
        return render_template('profile_writer.html', total_post=total_post, post_writer=post.author, filename=filename, posts=posts)


@app.route("/profile/user_id/post<username>/", methods=['GET', 'POST'])
def username_profile(username):
    user = User.query.filter(User.username==username).first()
    post = Post.query.filter(Post.user_id==user.id).first()
    posts = Post.query.filter(Post.user_id == post.author.id).order_by(Post.date_posted.desc())[:1]
    total_post = Post.query.filter(Post.author==post.author).count()
    filename = '/profile_img/'+post.author.image_file
    if post.author == current_user:
        return redirect(url_for('user_profile'))
    else:
        return render_template('profile_writer.html', total_post=total_post, post_writer=post.author, filename=filename, posts=posts)


@app.route("/leaderboard")
def leaderboard_page():    
    data = db.session.query(User.username, func.count(Post.user_id)).join(User).group_by(Post.user_id).order_by(func.count(Post.user_id).desc()).all()[:10]
    return render_template('leaderboard.html', data=data)


@app.route("/addfriend<int:user_id>", methods=["GET", "POST"])
@login_required
def addfriend(user_id):
    post = Post.query.get_or_404(user_id)   
    posts = Post.query.filter(Post.user_id == post.author.id).order_by(Post.date_posted.desc())[:1]
    total_post = Post.query.filter(Post.author==post.author).count()
    filename = '/profile_img/'+post.author.image_file
    addfriend = Friends(user_sender=current_user.id, sentto=post.author.id)
    exists = Friends.query.filter(Friends.status == '0', Friends.user_sender==current_user.id, Friends.sentto==user_id).scalar()
    if exists:
        flash("Your Friend request has already send", 'warning')
    else:
        db.session.add(addfriend)
        db.session.commit()
        flash("Your Friend request has send", "success")
    return render_template('profile_writer.html', total_post=total_post, post_writer=post.author, filename=filename, posts=posts)


@app.route("/post/<int:post_id>/comment", methods=["GET", "POST"])
@login_required
def comment_post(post_id):
    post = Post.query.get_or_404(post_id)
    form = CommentForm()
    if form.validate_on_submit():
        comment1 = Comment(comment=form.comment.data, postid=post_id, userid=current_user.id)
        db.session.add(comment1)
        db.session.commit()
        flash("Your comment has been added to the post", "success")
        return redirect(url_for('home'))
    flash('comment did not passed', 'danger')
    return redirect(url_for('post'), post_id=post_id)


@app.route("/request_send")
@login_required
def request_sent():
    friends_username=db.session.query(User.id, User.username, User.email, User.image_file, Friends).filter(Friends.status == '0', Friends.user_sender==current_user.id, User.id==Friends.sentto).all()
    return render_template('request_sent.html', friends_username=friends_username)


@app.route("/request_receive")
@login_required
def request_receive():
    friends_username=db.session.query(User.id, User.username, User.email, User.image_file, Friends).filter(Friends.status == '0', Friends.sentto==current_user.id, User.id==Friends.user_sender).all()
    return render_template('request_receive.html', friends_username=friends_username)


@app.route("/confirmed_friend")
@login_required
def confirmed_friend():
    friends_username=db.session.query(User.id, User.username, User.email, User.image_file, Friends).filter(Friends.status == '1', Friends.sentto==current_user.id, User.id==Friends.user_sender).all()
    return render_template('confirmed_friend.html', friends_username=friends_username)


@app.route("/block_friend_request")
@login_required
def block_friend_request():
    friends_username=db.session.query(User.id, User.username, User.email, User.image_file, Friends).filter(Friends.status == '2', Friends.sentto==current_user.id, User.id==Friends.user_sender).all()
    return render_template('block_friend.html', friends_username=friends_username)


@app.route("/accept_friend/<userid>", methods=['GET','POST'])
@login_required
def accept_friend(userid):
    friend = Friends.query.filter(Friends.status == '0', Friends.sentto==current_user.id, Friends.user_sender==userid).first()
    friend.status='1'
    db.session.commit()
    flash('Friend added', 'success')
    return redirect(url_for('confirmed_friend'))


@app.route("/block_friend/<userid>", methods=['GET','POST'])
@login_required
def block_friend(userid):
    friend = Friends.query.filter(Friends.status == '0', Friends.sentto==current_user.id, Friends.user_sender==userid).first()
    friend.status='2'
    db.session.commit()
    flash('User blocked', 'success')
    return redirect(url_for('block_friend_request'))


@app.route("/change_password", methods=["GET","POST"])
@login_required
def change_password():
    form=PasswordForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.old_password.data):
            if form.new_password.data == form.new_confirm_password.data:
                hashed_password = bcrypt.generate_password_hash(form.new_confirm_password.data).decode('utf-8')
                current_user.password = hashed_password
                db.session.commit()
                flash('password changed successfully', 'success')
                return redirect(url_for('user_profile_update'))
            else:
                flash('new password does not match with confirm password', 'danger')
        else:
            flash('password wrong', 'danger')
    return render_template('change_password.html', current_user=current_user, form=form)


@app.route("/like<int:post_id>", methods=["GET", "POST"])
@login_required
def like(post_id):
    post = Post.query.get_or_404(post_id)
    addlike = Reaction(postid=post_id, user_id=current_user.id, reaction="1", btn_color='primary')
    count = Reaction.query.filter(Reaction.reaction == '1', Reaction.postid==post_id).count()
    remove_like = Reaction.query.filter(Reaction.reaction == '1', Reaction.postid==post_id, Reaction.user_id==current_user.id).scalar()
    again_like = Reaction.query.filter(Reaction.reaction == '0', Reaction.postid==post_id, Reaction.user_id==current_user.id).scalar()
    convert_dislike_to_like = Reaction.query.filter(Reaction.reaction == '2', Reaction.postid==post_id, Reaction.user_id==current_user.id).first()
    if remove_like:
        remove_like.reaction="0"
        remove_like.btn_color='none'
        db.session.commit()
        flash("You remove like", "success")
        return redirect(url_for('home'))
    elif again_like:
        again_like.reaction="1"
        again_like.btn_color='primary'
        db.session.commit()
        flash("You like the post", "success")
    elif convert_dislike_to_like:
        convert_dislike_to_like.reaction="1"
        convert_dislike_to_like.btn_color='primary'
        db.session.commit()
        flash("You disliked become like", "success")
    else:
        db.session.add(addlike)
        db.session.commit()
        flash("You liked the post", "success")
    return redirect(url_for('post', post_id=post_id))


@app.route("/dislike<int:post_id>", methods=["GET", "POST"])
@login_required
def dislike(post_id):
    post = Post.query.get_or_404(post_id)
    adddislike = Reaction(postid=post_id, user_id=current_user.id, reaction="2", btn_color='danger')
    count = Reaction.query.filter(Reaction.reaction == '2', Reaction.postid==post_id).count()
    remove_dislike = Reaction.query.filter(Reaction.reaction == '2', Reaction.postid==post_id, Reaction.user_id==current_user.id).scalar()
    again_dislike = Reaction.query.filter(Reaction.reaction == '0', Reaction.postid==post_id, Reaction.user_id==current_user.id).scalar()
    convert_like_to_dislike = Reaction.query.filter(Reaction.reaction == '1', Reaction.postid==post_id, Reaction.user_id==current_user.id).first()
    if remove_dislike:
        remove_dislike.reaction="0"
        remove_dislike.btn_color='none'
        db.session.commit()
        flash("You remove dislike", "success")
        return redirect(url_for('home'))
    elif again_dislike:
        again_dislike.reaction="2"
        again_dislike.btn_color='danger'
        db.session.commit()
        flash("You dislike the post", "success")
    elif convert_like_to_dislike:
        convert_like_to_dislike.reaction="2"
        convert_like_to_dislike.btn_color='danger'
        db.session.commit()
        flash("Your like become dislike", "success")
    else:
        db.session.add(adddislike)
        db.session.commit()
        flash("You disliked the post", "success")
    return redirect(url_for('post', post_id=post_id))


@app.route("/favourite<int:post_id>", methods=["GET", "POST"])
@login_required
def favourite(post_id):
    post = Post.query.get_or_404(post_id)
    exists=Favourite.query.filter(Favourite.post_id==post_id, Favourite.user_id==current_user.id).scalar()
    addfavourite = Favourite(post_id=post_id, user_id=current_user.id)
    if exists:
        flash('this post already in favourite', 'warning')
    else:
        db.session.add(addfavourite)
        db.session.commit()
        flash("post add to favourite", "success")
    return redirect(url_for('home'))


@app.route("/favourite_show", defaults={"page_num": 1})
@app.route("/favourite_show<int:page_num>", methods=['GET', 'POST'])
@login_required
def favourite_show(page_num=1):
    comt_count = db.session.query(Post.id, func.count(Comment.postid)).join(Comment).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    like_count = db.session.query(Post.id, func.count(Reaction.reaction)).filter(Reaction.reaction=='1').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    dislike_count = db.session.query(Post.id, func.count(Reaction.reaction)).filter(Reaction.reaction=='2').join(Reaction).group_by(Post.id).order_by(func.count(Post.id).desc()).all()
    posts = db.session.query(User, User.id, User.username, User.image_file,Post.id, Post.title, Post.content, Post.date_posted, Post.user_id, Post.image).join(Post, Favourite).filter(Favourite.user_id==current_user.id).order_by(Post.date_posted.desc()).paginate(per_page=5, page=page_num)
    like_exists=db.session.query(Post.id, Reaction.user_id, Reaction.btn_color).filter(Reaction.reaction=='1').join(Reaction).all()
    dislike_exists=db.session.query(Post.id, Reaction.user_id, Reaction.btn_color).filter(Reaction.reaction=='2').join(Reaction).all()
    return render_template('favourite.html', posts=posts, comt_count=comt_count, like_count=like_count, dislike_count=dislike_count, like_exists=like_exists, dislike_exists=dislike_exists)


if __name__ == '__main__':
    app.run(debug=True)

    