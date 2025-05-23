from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = 'supersecretkey' # For development only
users = []

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'] # Passwords can have leading/trailing spaces

        if not username or not password:
            flash('Username and password cannot be empty!', 'error')
            return render_template('register.html')

        # Check if username already exists (case-insensitive check)
        if any(user['username'].lower() == username.lower() for user in users):
            flash('Username already taken. Please choose another.', 'error')
            return render_template('register.html')
        # In a real app, you'd hash the password here
        users.append({'username': username, 'password': password})
        # For now, just a simple confirmation. We'll redirect to a success page later.
        # Also, we'll print users to console for verification during development
        print(users)
        return redirect(url_for('registration_success')) # Redirect to a success page
    return render_template('register.html')

@app.route('/registration-success')
def registration_success():
    return render_template('registration_success.html')

if __name__ == '__main__':
    app.run(debug=True)
