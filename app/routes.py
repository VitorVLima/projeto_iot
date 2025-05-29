from app import app, db, bcrypt
from flask import request, jsonify
from .models import User
import requests
from email_validator import validate_email, EmailNotValidError
from functools import wraps
import jwt
import datetime
from time import sleep
import json
import paho.mqtt.client as mqtt

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

ONESIGNAL_APP_ID = "d99c0403-92be-4768-a8d3-9d350711bbbe" # Substitua pelo seu App ID
ONESIGNAL_REST_API_KEY = "os_v2_app_3goaia4sxzdwrkgttu2qoen3xzklhitstraercelynyr6hig2iwns6aj3762dioip4oswlby3gg5zookpzdfet6vvzo7q4psmthjg3q" # Substitua pela sua REST API Key

def send_onesignal_notification(player_id, title, body, data_payload=None):
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        "Authorization": f"Basic {ONESIGNAL_REST_API_KEY}"
    }

    payload = {
        "app_id": ONESIGNAL_APP_ID,
        "include_player_ids": [player_id],
        "contents": {"en": body},
        "headings": {"en": title},
    }

    if data_payload:
        payload["data"] = data_payload

    try:
        response = requests.post("https://onesignal.com/api/v1/notifications", headers=headers, json=payload)
        response.raise_for_status()
        print(f"Notificação OneSignal enviada com sucesso: {response.json()}")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Erro ao enviar notificação OneSignal: {e}")
        return False

# --- Configurações MQTT (já existentes no seu código) ---
MQTT_BROKER = "broker.hivemq.com"
MQTT_PORT = 1883
MQTT_ALERT_TOPIC = "sensor/alerta/app1234" # Seu tópico onde o ESP32 publica alertas

# Callback de conexão MQTT
def on_connect(client, userdata, flags, rc):
    print(f"Conectado ao broker MQTT com código {rc}")
    client.subscribe(MQTT_ALERT_TOPIC)
    print(f"Assinado ao tópico: {MQTT_ALERT_TOPIC}")

# Callback de mensagem MQTT
def on_message(client, userdata, msg):
    print(f"Mensagem MQTT recebida no tópico {msg.topic}: {msg.payload.decode()}")
    try:
        dados_alerta = json.loads(msg.payload.decode())

        batimentos = dados_alerta.get("batimentos")
        aceleracao = dados_alerta.get("aceleracao")

        # Inicializa as mensagens de alerta
        alerta_batimentos = ""
        alerta_aceleracao = ""
        has_alert = False

        # --- Lógica de Alerta para Batimentos ---
        if batimentos is not None: # Verifica se o valor existe
            if batimentos < 5:
                alerta_batimentos = f"Batimentos cardíacos muito baixos: {batimentos} BPM!"
                has_alert = True
            elif batimentos > 95:
                alerta_batimentos = f"Batimentos cardíacos muito altos: {batimentos} BPM!"
                has_alert = True

        # --- Lógica de Alerta para Aceleração ---
        if aceleracao is not None and aceleracao == 0:
            alerta_aceleracao = "Aceleração detectada igual a 0. Dispositivo pode estar parado!"
            has_alert = True

        # Se houver qualquer tipo de alerta, envie a notificação
        if has_alert:
            # Concatena as mensagens de alerta
            full_alert_message = ""
            if alerta_batimentos:
                full_alert_message += alerta_batimentos
            if alerta_aceleracao:
                if full_alert_message: # Adiciona uma quebra de linha se já houver uma mensagem
                    full_alert_message += "\n"
                full_alert_message += alerta_aceleracao

            # Busca os usuários para notificar
            # Em um cenário real, você provavelmente filtraria por usuários
            # associados a este ESP32 ou a este alerta específico.
            # Por simplicidade, estamos notificando todos os usuários com player_id.
            users_to_notify = User.query.filter(User.onesignal_player_id.isnot(None)).all()

            for user in users_to_notify:
                if user.onesignal_player_id:
                    print(f"Enviando alerta para {user.email}...")
                    send_onesignal_notification(
                        user.onesignal_player_id,
                        "🚨 Alerta de Saúde Urgente!",
                        full_alert_message,
                        dados_alerta # Envia os dados brutos do ESP32 como payload de dados
                    )
        else:
            print("Dados normais, sem alerta necessário.")

    except json.JSONDecodeError:
        print("Payload MQTT não é um JSON válido.")
    except Exception as e:
        print(f"Erro ao processar mensagem MQTT: {e}")

# --- Inicialização do Cliente MQTT (fora das funções) ---
mqtt_client = mqtt.Client()
mqtt_client.on_connect = on_connect
mqtt_client.on_message = on_message
mqtt_client.connect(MQTT_BROKER, MQTT_PORT, 60)
mqtt_client.loop_start() # Inicia o loop em um thread separado para não bloquear o Flask

@app.route('/registrar_player_id', methods=['POST'])
@token_required # Associe o Player ID ao usuário logado
def registrar_player_id(current_user):
    data = request.get_json()
    onesignal_player_id = data.get('onesignal_player_id')

    if not onesignal_player_id:
        return jsonify({"erro": "OneSignal Player ID ausente"}), 400

    current_user.onesignal_player_id = onesignal_player_id
    db.session.commit()
    return jsonify({"status": "OneSignal Player ID registrado com sucesso"})

