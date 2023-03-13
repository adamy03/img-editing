from flask import Blueprint, render_template, request, flash, redirect, url_for, send_from_directory
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename 
from . import db, IM_PATH
from flask_login import login_user, login_required, logout_user, current_user
from PIL import Image
import os
import numpy as np
import random
from skimage.util import random_noise
import cv2

auth = Blueprint('auth', __name__)
currIM = None

@auth.route('/login', methods=['GET', 'POST']) #set up different pages
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()

        if user:
            if check_password_hash(user.password, password):
                flash('Logged in!', category='success')
                login_user(user, remember=True)
                return redirect(url_for('views.home'))
            else:
                flash('Incorrect password, try again.', category='error')
        else:
            flash('Email does not exist.', category='error')

    return render_template('login.html', user=current_user)
                
@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))

@auth.route('/sign-up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('firstName')
        password1 = request.form.get('password1')
        password2 = request.form.get('password2')

        user = User.query.filter_by(email=email).first()

        if user:
            flash('Email already exists.', category='error')
        elif len(email) < 4:
            flash('Email must be greater than 3 characters.', category='error')
        elif len(first_name) < 2:
            flash('First name must be greater than 1 character.', category='error')
        elif password1 != password2:
            flash('Passwords don\'t match.', category='error')
        elif len(password1) < 7:
            flash('Password must be at least 7 characters.', category='error')
        else:
            new_user = User(email=email, first_name=first_name, password=generate_password_hash(password1, method='sha256'))
            db.session.add(new_user)
            db.session.commit()
            flash('Success', category='success')
            login_user(new_user, remember=True)
            return redirect(url_for('views.home'))
            
    return render_template('sign_up.html', user=current_user)

@auth.route('/', methods=['GET', 'POST'])
@login_required
def home(): 
    return render_template('home.html', user=current_user)

@auth.route('/image', methods=['GET', 'POST'])
@login_required
def image():
    return render_template('editor.html', user=current_user)

@auth.route('/editor', methods=['GET', 'POST'])
@login_required
def editor():
    return render_template('editor.html', user=current_user)

@auth.route('/upload', methods=['POST'])
@login_required
def upload_image():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', category='error')
            return redirect(url_for('views.image'))
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', category='error')
            return redirect(url_for('views.image'))
        if file:
            filename = secure_filename(file.filename)
            file.save(os.path.join(IM_PATH, filename))
            return redirect(url_for('views.image'))

@auth.route('/get_image', methods=['POST'])
@login_required
def displayImage():
    img_file_path = os.path.join('static\images', random.choice(os.listdir(IM_PATH)))

    img = Image.open('website\\'+img_file_path)
    img = np.asarray(img, dtype=np.float32)

    row,col,ch = img.shape
    gauss = np.random.normal(0, 0.01,(row,col,ch))
    gauss = gauss.reshape(row,col,ch)
    
    noise_img = (img + gauss)
    cv2.imwrite(os.path.join('website/static/edited/', img_file_path.split('\\')[-1]), noise_img)
    # noise_img = noise_img.save(os.path.join('website/static/edited/', img_file_path.split('\\')[-1]))

    return render_template('editor.html', user=current_user, img=os.path.join('static\edited',img_file_path.split('\\')[-1]))
