from flask import Flask, render_template, request, redirect, session, flash
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta
from flask_bcrypt import Bcrypt
import os
import re
import uuid

app = Flask(__name__)
app.secret_key = '1PwshLFwoa9QT4M0'  # Thay bằng khóa bí mật của bạn
app.secret_key = os.getenv('SECRET_KEY', 'your-default-secret-key')

# Cấu hình kết nối MongoDB
app.config['MONGO_URI'] = 'mongodb://localhost:27017/ntddcomeback'  # Thay 'mydatabase' bằng tên DB của bạn
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

mongo = PyMongo(app)
bcrypt = Bcrypt(app)

# Tạo bảng (collection) người dùng nếu chưa tồn tại
users_collection = mongo.db.users
sessions_collection = mongo.db.sessions

def is_valid_email(email):
    return re.match(r'^[^@]+@[^@]+\.[^@]+$', email)

def is_strong_password(password):
    return len(password) >= 8 and any(char.isdigit() for char in password)

def store_login_session(user_id, session_id, user_agent):
    sessions_collection.insert_one({
        'user_id': user_id,
        'session_id': session_id,
        'user_agent': user_agent
    })

def check_and_manage_sessions(user_id, current_session_id):
    # Giới hạn số lượng phiên đăng nhập
    max_sessions = 5
    sessions = list(sessions_collection.find({'user_id': user_id}))
    if len(sessions) >= max_sessions:
        # Xóa phiên cũ nhất nếu số phiên đăng nhập vượt quá giới hạn
        oldest_session = min(sessions, key=lambda s: s['timestamp'])
        sessions_collection.delete_one({'session_id': oldest_session['session_id']})

# Route cho đăng ký
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not is_valid_email(email):
            flash('Địa chỉ email không hợp lệ.')
            return redirect('/signup')

        if not is_strong_password(password):
            flash('Mật khẩu phải có ít nhất 8 ký tự và chứa ít nhất một số.')
            return redirect('/signup')

        existing_user = users_collection.find_one({'username': username})
        if existing_user:
            flash('Tên người dùng đã tồn tại. Vui lòng chọn tên khác.')
            return redirect('/signup')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users_collection.insert_one({
            'username': username,
            'email': email,
            'password': hashed_password
        })

        flash('Đăng ký thành công! Vui lòng đăng nhập.')
        return redirect('/login')

    return render_template('signup.html')

# Route cho đăng nhập
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = users_collection.find_one({'username': username})
        if user and bcrypt.check_password_hash(user['password'], password):
            session_id = str(uuid.uuid4())  # Tạo ID phiên mới
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            session['session_id'] = session_id  # Lưu ID phiên trong session

            # Lưu thông tin phiên đăng nhập
            user_agent = request.headers.get('User-Agent')
            store_login_session(session['user_id'], session_id, user_agent)
            
            # Quản lý số lượng phiên đăng nhập
            check_and_manage_sessions(session['user_id'], session_id)
            
            flash('Đăng nhập thành công!')
            return redirect('https://ntdd.site/menu.html')  # Chuyển hướng đến URL mong muốn
        else:
            flash('Tên người dùng hoặc mật khẩu không đúng.')
            return redirect('/login')

    return render_template('login.html')

# Route cho trang menu
@app.route('/menu')
def menu():
    if 'user_id' in session:
        return redirect('https://ntdd.site/menu.html')  # Chuyển hướng đến URL mong muốn
    else:
        flash('Bạn cần phải đăng nhập để truy cập trang này.')
        return redirect('/login')

# Route cho trang cá nhân (Dashboard)
@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        return f"Chào mừng {session['username']} đến với trang cá nhân!"
    return redirect('/login')

# Route cho đăng xuất
@app.route('/logout')
def logout():
    session.clear()
    flash('Bạn đã đăng xuất.')
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)
