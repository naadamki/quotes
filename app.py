import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import requests
from dotenv import load_dotenv

load_dotenv()

FAVQS_BASE = "https://favqs.com/api"
FAVQS_API_KEY = os.getenv('FAVQS_API_KEY')
SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')

app = Flask(__name__)
app.secret_key = SECRET_KEY


def favqs_request(method, path, json=None, headers=None, use_api_key=False, user_token=None):
    url = f"{FAVQS_BASE}{path}"
    hdrs = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    if headers:
        hdrs.update(headers)
    if use_api_key and FAVQS_API_KEY:
        hdrs['Authorization'] = f'Token token="{FAVQS_API_KEY}"'
    if user_token:
        # user session token overrides api key if provided
        hdrs['Authorization'] = f'Token token="{user_token}"'

    resp = requests.request(method, url, json=json, headers=hdrs)
    try:
        data = resp.json()
    except Exception:
        data = {'error': 'non-json response', 'status': resp.text}
    return resp.status_code, data


@app.route('/')
def index():
    status, data = favqs_request('GET', '/qotd')
    quote = None
    if status == 200:
        quote = data.get('quote') or data
    else:
        flash('Could not fetch Quote of the Day', 'error')
    return render_template('index.html', quote=quote)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        login = request.form.get('login')
        email = request.form.get('email')
        password = request.form.get('password')
        payload = {'user': {'login': login, 'email': email, 'password': password}}
        status, data = favqs_request('POST', '/users', json=payload, use_api_key=True)
        if status in (200, 201):
            flash('Account created successfully', 'success')
            session['user'] = data.get('user') or data
            return redirect(url_for('index'))
        else:
            flash(str(data), 'error')
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_field = request.form.get('login')
        password = request.form.get('password')
        payload = {'session': {'login': login_field, 'password': password}}
        # FavQs uses singular /session endpoint and needs API key
        status, data = favqs_request('POST', '/session', json=payload, use_api_key=True)
        if status in (200, 201):
            flash('Logged in successfully', 'success')
            session['user_session'] = data
            # store token if present
            token = None
            if isinstance(data, dict):
                token = data.get('user_token') or data.get('token')
            if token:
                session['token'] = token
            return redirect(url_for('index'))
        else:
            flash(str(data), 'error')
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
def logout():
    token = session.get('token')
    # Destroy session at FavQs: DELETE /session
    status, data = favqs_request('DELETE', '/session', user_token=token)
    session.pop('user_session', None)
    session.pop('token', None)
    flash('Logged out', 'success')
    return redirect(url_for('index'))


@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        payload = {'user': {'email': email}}
        # Using API key for user operations
        status, data = favqs_request('POST', '/users/forgot_password', json=payload, use_api_key=True)
        if status in (200, 201):
            flash('If that email exists, a password reset link has been sent.', 'success')
            return redirect(url_for('login'))
        else:
            flash(str(data), 'error')
    return render_template('forgot.html')


@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        token = request.form.get('token')
        password = request.form.get('password')
        payload = {'user': {'token': token, 'password': password}}
        status, data = favqs_request('POST', '/users/reset_password', json=payload, use_api_key=True)
        if status in (200, 201):
            flash('Password reset successfully', 'success')
            return redirect(url_for('login'))
        else:
            flash(str(data), 'error')
    return render_template('reset.html')


@app.route('/profile', methods=['GET', 'POST'])
def profile():
    token = session.get('token')
    if request.method == 'POST':
        login = request.form.get('login')
        email = request.form.get('email')
        payload = {'user': {'login': login, 'email': email}}
        status, data = favqs_request('PATCH', '/users', json=payload, user_token=token)
        if status in (200, 201):
            flash('Profile updated', 'success')
            return redirect(url_for('profile'))
        else:
            flash(str(data), 'error')
    user = session.get('user')
    return render_template('profile.html', user=user)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
