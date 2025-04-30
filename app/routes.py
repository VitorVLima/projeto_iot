from app import app, db, bcrypt
from flask import request, jsonify
from .models import User
import requests
from email_validator import validate_email, EmailNotValidError
from functools import wraps
import jwt
import datetime
from time import sleep

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split(" ")[1]  
        
            except IndexError:
                return jsonify({'erro': 'Token malformado'}), 401

        if not token:
            return jsonify({'erro': 'Token ausente'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.get(data['user_id'])
        except Exception as e:
            return jsonify({'erro': 'Token invalido ou expirado'}), 401

        return f(current_user, *args, **kwargs)
    return decorated


@app.route("/register_admin", methods=['POST'])
def register_admin():
    print("Recebendo requisição POST")
    data = request.get_json()
    print("Dados recebidos:", data)

    email = data.get('email')
    password = data.get('password')
    mqtt_topic_prefix = data.get('mqtt_topic_prefix')

    if not email or not password or not mqtt_topic_prefix:
        return jsonify({"erro": "Campos obrigatórios faltando"}), 400

    try:
        valid = validate_email(email)
        email = valid.email
    except EmailNotValidError as e:
        return jsonify({"erro": f"Email invalido: {str(e)}"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"erro": "Email ja existe"}), 409

    if User.query.filter_by(mqtt_topic_prefix=mqtt_topic_prefix).first():
        return jsonify({"erro": "Este prefixo MQTT ja esta em uso"}), 403

    hashed_pw = bcrypt.generate_password_hash(password)
    admin = User(
        email=email,
        password=hashed_pw,
        is_admin=True,
        mqtt_topic_prefix=mqtt_topic_prefix
    )
    db.session.add(admin)
    db.session.commit()

    return jsonify({"status": "Admin cadastrado com sucesso"})

@app.route('/create_user', methods=['POST'])
@token_required
def create_user(current_user):
    print(current_user.email)

    if not current_user.is_admin:
        return jsonify({"erro": "Usuario nao possui permissao de criar novos usuarios"})
    
    data = request.get_json()
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    try:
        valid = validate_email(email)
        email = valid.email  
    except EmailNotValidError as e:
        return jsonify({"erro": f"Email invalido: {str(e)}"}), 400

    if not username or not email or not password:
        return jsonify({"erro": "Campos obrigatórios faltando"}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({"erro": "Este email ja esta em uso"}), 409

    hashed_pw = bcrypt.generate_password_hash(password)
    new_user = User(
        username=username,
        email=email,
        password=hashed_pw,
        is_admin=False,
        admin_id=current_user.id,
        mqtt_topic_prefix= current_user.mqtt_topic_prefix
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"status": "usuario criado com sucesso"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data.get("identifier")  
    password = data.get("password")

    if not identifier or not password:
        return jsonify({"erro": "Digite usuário e senha"}), 400

    user = User.query.filter(
        User.email == identifier).first()

    if user and bcrypt.check_password_hash(user.password, password):
        token = jwt.encode({
            "user_id": user.id,
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=4)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        return jsonify({
            "status": "conectado",
            "is_admin": user.is_admin,
            "token": token,
            "mqtt_topic_prefix": user.mqtt_topic_prefix if user.is_admin else user.admin.mqtt_topic_prefix
        })

    return jsonify({"erro": "Credenciais inválidas"}), 401

    
@app.route('/logout', methods=['POST', 'GET'])
@token_required
def logout(current_user):
    print(request.headers)
    

    return jsonify({"status": "desconectado"})


alerta_enviado = False
9

@app.route('/delete_user/<int:user_id>', methods=['DELETE'])
@token_required
def deletar_usuario(current_user, user_id):
    if not current_user.is_admin:
        return jsonify({"erro": "Permissão negada"}), 403

    usuario = User.query.get(user_id)
    if not usuario:
        return jsonify({"erro": "Usuário não encontrado"}), 404

    if usuario.admin_id != current_user.id:
        return jsonify({"erro": "Você não pode deletar este usuário"}), 403

    db.session.delete(usuario)
    db.session.commit()

    return jsonify({"status": "Usuário deletado com sucesso"})

@app.route('/listar_usuarios', methods=['GET'])
@token_required
def listar_usuarios(current_user):
    if not current_user.is_admin:
        return jsonify({"erro": "Acesso não autorizado"}), 403

    usuarios = User.query.filter_by(admin_id=current_user.id).all()
    resultado = []
    for u in usuarios:
        resultado.append({
            "id": u.id,
            "username": u.username,
            "email": u.email
        })

    return jsonify(resultado)



