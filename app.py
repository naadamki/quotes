from flask import Flask, render_template, request, redirect, url_for, session, flash
import requests
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'

FAVQS_API_BASE = 'https://favqs.com/api'
FAVQS_API_KEY = 'your-favqs-api-key'

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    # Get quote of the day
    headers = {'Authorization': f'Token token="{FAVQS_API_KEY}"'}
    try:
        response = requests.get(f'{FAVQS_API_BASE}/qotd', headers=headers)
        qotd = response.json().get('quote', {})
    except:
        qotd = None
    
    return render_template('index.html', qotd=qotd)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        data = {
            'user': {
                'login': request.form['username'],
                'email': request.form['email'],
                'password': request.form['password']
            }
        }
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(f'{FAVQS_API_BASE}/users', json=data, headers=headers)
            if response.status_code == 200:
                flash('Account created successfully! Please login.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Error creating account. Please try again.', 'error')
        except:
            flash('Error connecting to server.', 'error')
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = {
            'user': {
                'login': request.form['username'],
                'password': request.form['password']
            }
        }
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(f'{FAVQS_API_BASE}/session', json=data, headers=headers)
            if response.status_code == 200:
                result = response.json()
                session['user_token'] = result.get('User-Token')
                session['username'] = result.get('login')
                flash('Logged in successfully!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid credentials.', 'error')
        except:
            flash('Error connecting to server.', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'user_token' in session:
        headers = {'Authorization': f'Token token="{session["user_token"]}"'}
        try:
            requests.delete(f'{FAVQS_API_BASE}/session', headers=headers)
        except:
            pass
    
    session.clear()
    flash('Logged out successfully!', 'success')
    return redirect(url_for('index'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        data = {'user': {'email': request.form['email']}}
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.post(f'{FAVQS_API_BASE}/users/forgot_password', json=data, headers=headers)
            flash('If the email exists, you will receive password reset instructions.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Error connecting to server.', 'error')
    
    return render_template('forgot_password.html')

@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        data = {
            'user': {
                'reset_password_token': request.form['token'],
                'password': request.form['password']
            }
        }
        headers = {'Content-Type': 'application/json'}
        
        try:
            response = requests.put(f'{FAVQS_API_BASE}/users/reset_password', json=data, headers=headers)
            if response.status_code == 200:
                flash('Password reset successfully!', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid or expired reset token.', 'error')
        except:
            flash('Error connecting to server.', 'error')
    
    return render_template('reset_password.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)