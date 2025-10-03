from flask import Flask, render_template, redirect, url_for, flash
from flask_wtf.csrf import CSRFProtect
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
# Importamos los formularios definidos en forms.py
from forms import RegistrationForm, LoginForm
import os
import secrets

# Inicialización de la aplicación
app = Flask(__name__)
# Usar una clave secreta generada dinámicamente o de una variable de entorno (Mejor Práctica)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(16))
# app.config['SECRET_KEY'] = 'clave_secreta_segura' # La clave original, menos segura.

csrf = CSRFProtect(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor, inicia sesión para acceder a esta página."
login_manager.login_message_category = "warning"

# --- Almacenamiento de Usuarios (en memoria, no persistente) ---
# En una aplicación real, usarías una base de datos.
users = {}
next_id = 1

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        # Es crucial que el ID sea un string para Flask-Login
        self.id = str(id)
        self.username = username
        self.password_hash = password_hash

    # Método requerido por UserMixin
    def get_id(self):
        return self.id

@login_manager.user_loader
def load_user(user_id):
    # Convertimos el ID de string a int para buscar en el diccionario 'users'
    try:
        return users.get(int(user_id))
    except ValueError:
        return None

# --- Rutas de la Aplicación ---

@app.route('/')
def home():
    return render_template('base.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    global next_id
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        
        # FIX: Evitar registro de nombres de usuario duplicados
        if any(user.username == username for user in users.values()):
            flash("El nombre de usuario ya está registrado. Por favor, elige otro.", "danger")
            return render_template('register.html', form=form)
        
        # Hashear la contraseña antes de guardarla
        password_hash = generate_password_hash(form.password.data)
        
        # Crear y guardar el nuevo usuario
        user = User(next_id, username, password_hash)
        users[next_id] = user
        next_id += 1
        
        flash("Registro exitoso. Ya puedes iniciar sesión.", "success")
        return redirect(url_for('login'))
        
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username_data = form.username.data
        password_data = form.password.data
        
        # Buscar usuario
        user = next((u for u in users.values() if u.username == username_data), None)
        
        if user and check_password_hash(user.password_hash, password_data):
            login_user(user)
            # Redirigir al 'next' si existe, si no, a 'profile'
            next_page = request.args.get('next')
            flash(f"¡Bienvenido, {user.username}! Has iniciado sesión con éxito.", "success")
            return redirect(next_page or url_for('profile'))
        
        flash("Credenciales inválidas. Verifica tu usuario y contraseña.", "danger")
        
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for('home'))

@app.route('/profile')
@login_required
def profile():
    # current_user es proporcionado por Flask-Login
    return render_template('profile.html', username=current_user.username, user_id=current_user.id)

# Manejo de errores
@app.errorhandler(401)
def unauthorized(e):
    flash("No tienes autorización para acceder a esa página. Inicia sesión.", "warning")
    return redirect(url_for('login'))

if __name__ == '__main__':
    # Importamos request aquí para evitar un error de importación circular
    from flask import request 
    app.run(debug=True)
