"""
Emilee Mapanao
July 10, 2021
Program to produce a website about dinosaurs

"""
import datetime
import re
import flask
from flask import Flask, request, session, render_template, redirect, url_for

app = Flask(__name__)
app.secret_key = "beep"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"


@app.route('/register/', methods=['GET', 'POST'])
def register():
    """
    New user registration
    """
    error = None
    if request.method == 'POST':
        f = open('registration.txt', 'r+')
        blacklisted = open('Blacklisted.txt', 'r')
        password = (request.form['password'])
        if request.form['password'] in blacklisted.read():
            error = 'Weak or compromised password. Please select new password'
        elif len(password) < 12:
            error = 'Password too short'
        elif not re.search("[a-z]", password):
            error = 'Password must include lowercase letter'
        elif not re.search("[A-Z]", password):
            error = 'Password must include uppercase letter'
        elif not re.search('[0-9]', password):
            error = 'Password must include a number'
        elif not re.search('[!@#$%^&*]', password):
            error = 'Password must include special character'
        elif request.form['email'] in f.read():
            error = 'Email already registered'
        else:
            # Add email and password to file
            f.writelines(request.form['email'] + " " + password + "\n")
            f.close()
            return redirect(url_for('homepage'))
    return render_template('Register.html', error=error)


@app.route('/passwordupdate/', methods=['GET', 'POST'])
def password_update():
    """
    Method to update a current users password
    """
    error = None
    if 'email' in session:
        if request.method == 'POST':
            with open('registration.txt', 'r+') as loginfile:
                lines = loginfile.readlines()
                blacklisted = open('Blacklisted.txt', 'r')
                new_password = (request.form['new_password'])
                password = request.form['password']
                if password + "\n" in blacklisted.read():
                    error = 'Weak or compromised password. Please select new password'
                elif len(new_password) < 12:
                    error = 'Password too short'
                elif not re.search("[a-z]", new_password):
                    error = 'Password must include lowercase letter'
                elif not re.search("[A-Z]", new_password):
                    error = 'Password must include uppercase letter'
                elif not re.search('[0-9]', new_password):
                    error = 'Password must include a number'
                elif not re.search('[!@#$%^&*]', new_password):
                    error = 'Password must include special character'
                elif (request.form['email'] + " " + request.form['password'] + "\n") not in lines:
                    error = "Invalid credentials"  # Must be active user
                else:
                    with open('registration.txt', 'r') as file:
                        lines = file.readlines()
                        file.close()
                        # Copy data from file and rewrite
                    with open('registration.txt', "w") as new_file:
                        new_file.write(request.form['email'] + " " + new_password + "\n")
                        for line in lines:
                            # Remove old password
                            if line.strip("\n") != request.form['email'] + " " + password:
                                new_file.write(line)
                        new_file.close()
                        error = "Password successfully updated!"

                    #return redirect(url_for('homepage'))
    return render_template('Password_update.html', error=error)


@app.route('/login/', methods=['GET', 'POST'])
def login():
    """
    Login page
    """
    error = None
    if request.method == 'POST':
        with open('registration.txt', 'r') as loginfile:
            if request.form['email'] + " " + request.form['password'] + "\n" in loginfile.readlines():
                session['email'] = request.form['email']
                return redirect(url_for('homepage'))
            else:
                # Create file of information with invalid logins
                error = 'Invalid credentials'
                f = open('Invalid Attempts.txt', 'a')
                f.writelines(str(datetime.datetime.now()))
                f.writelines("    ")
                f.writelines(flask.request.remote_addr)
                f.writelines("\n")

    return render_template('login.html', error=error)


@app.route('/', methods=['GET', 'POST'])
def homepage():
    """
   Homepage display after successful login
    """
    if 'email' in session:
        return render_template('homepage.html')
    else:
        return '<link rel= "stylesheet" type= "text/css" href= "/static/css/style.css"/>' \
               '<h1> Login required <br>' \
               '<a href="http://localhost:5000/login">Login</a>' \
               ' or <a href="http://localhost:5000/register">Sign up</a></h1>'


@app.route('/logout/')
def logout():
    """
    Method to logout user
    """
    if 'email' in session:
        session.pop('email', None)
        return render_template('logout.html')
    else:
        return '<link rel= "stylesheet" type= "text/css" href= "/static/css/style.css"/>' \
               '<h1> Already logged out </h1>' \
               '<a href="http://localhost:5000/login">Login</a>' \
               ' or <a href="http://localhost:5000/register">Sign up</a></h1>'


@app.route('/spinosaurus/')
def spinosaurus():
    """
    Method for spinosaurus.
    """
    if 'email' in session:
        full = datetime.datetime.now()
        date = (full.strftime("%B %d %Y,"))
        time = (full.strftime("%H:%M"))
        return render_template('spinosaurus.html', date=date, time=time)
    else:
        return '<link rel= "stylesheet" type= "text/css" href= "/static/css/style.css"/>' \
               '<h1> Login required <br>' \
               '<a href="http://localhost:5000/login">Login</a>' \
               ' or <a href="http://localhost:5000/register">Sign up</a></h1>'


@app.route('/trex/')
def trex():
    """
    Method for T-Rex webpage
    """
    if 'email' in session:
        full = datetime.datetime.now()
        date = (full.strftime("%B %d %Y,"))
        time = (full.strftime("%H:%M"))
        return render_template('trex.html', time=time, date=date)
    else:
        return '<link rel= "stylesheet" type= "text/css" href= "/static/css/style.css"/>' \
               '<h1> Login required <br>' \
               '<a href="http://localhost:5000/login">Login</a>' \
               ' or <a href="http://localhost:5000/register">Sign up</a></h1>'


@app.route('/mosasaurus/')
def mosasaurus():
    """
    Method for Mosasaurus webpage
    """
    if 'email' in session:
        full = datetime.datetime.now()
        date = (full.strftime("%B %d %Y,"))
        time = (full.strftime("%H:%M"))
        return render_template('mosasaurus.html', time=time, date=date)
    else:
        return '<link rel= "stylesheet" type= "text/css" href= "/static/css/style.css"/>' \
               '<h1> Login required <br>' \
               '<a href="http://localhost:5000/login">Login</a>' \
               ' or <a href="http://localhost:5000/register">Sign up</a></h1>'
