from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, EqualTo, Length, Email # Email se mantiene aunque no se use

# Formulario para el Registro de nuevos usuarios
class RegistrationForm(FlaskForm):
    # Etiqueta consistente y longitud mínima de 2 (como en app.py) y máxima de 20
    username = StringField('Nombre de Usuario', 
                           validators=[DataRequired(), Length(min=2, max=20)])
    
    # Contraseña con validación de longitud MÍNIMA de 6 (¡Buena práctica de seguridad!)
    password = PasswordField('Contraseña', 
                             validators=[DataRequired(), Length(min=6)])
                             
    # Confirmación de la contraseña, ahora con un mensaje de error específico
    confirm_password = PasswordField('Confirmar Contraseña', 
                                     validators=[DataRequired(), EqualTo('password', message='Las contraseñas deben coincidir.')])
                                     
    # Etiqueta consistente con el template HTML
    submit = SubmitField('Registrarse')

# Formulario para el Inicio de Sesión
class LoginForm(FlaskForm):
    # Etiqueta consistente
    username = StringField('Nombre de Usuario', 
                           validators=[DataRequired()])
                           
    password = PasswordField('Contraseña', 
                             validators=[DataRequired()])
                             
    # Etiqueta consistente
    submit = SubmitField('Iniciar Sesión')
