import os
import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from cryptography.fernet import Fernet
import paramiko

# --- Configuração Inicial ---
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
BACKUP_DIR = os.path.join(BASE_DIR, 'backups')
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'default_flask_secret_key_change_this_in_production' # Mude isso para produção!
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(BASE_DIR, 'instance', 'app.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

instance_path = os.path.join(BASE_DIR, 'instance')
if not os.path.exists(instance_path):
    os.makedirs(instance_path)

db = SQLAlchemy(app)

# --- Criptografia de Senhas ---
FERNET_KEY_FILE = os.path.join(BASE_DIR, "secret.key")
cipher_suite = None
if os.path.exists(FERNET_KEY_FILE):
    with open(FERNET_KEY_FILE, "rb") as key_file:
        FERNET_KEY = key_file.read()
    cipher_suite = Fernet(FERNET_KEY)
else:
    print(f"AVISO: Arquivo 'secret.key' não encontrado em {FERNET_KEY_FILE}. Será gerado um ao iniciar ou você pode gerar manualmente.")
    # Poderia gerar aqui, mas vamos deixar o app.py cuidar disso ou o usuário gerar.

def ensure_cipher_suite():
    global cipher_suite
    if cipher_suite is None:
        if os.path.exists(FERNET_KEY_FILE):
            with open(FERNET_KEY_FILE, "rb") as key_file:
                key = key_file.read()
            cipher_suite = Fernet(key)
        else:
            print(f"ERRO CRÍTICO: {FERNET_KEY_FILE} não encontrado e cipher_suite não inicializado.")
            # Em um app real, você não continuaria sem a chave.
            # Para o MVP, o app vai tentar gerar se não existir na primeira execução de cripto/decripto
            # Mas é melhor garantir que exista antes. O passo 4 deste script gera.
            raise Exception(f"{FERNET_KEY_FILE} não encontrado. Gere-o primeiro.")


def encrypt_password(password):
    ensure_cipher_suite()
    return cipher_suite.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    ensure_cipher_suite()
    return cipher_suite.decrypt(encrypted_password.encode()).decode()

# --- Modelos do Banco de Dados ---
class Device(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    ip_address = db.Column(db.String(100), nullable=False)
    ssh_port = db.Column(db.Integer, default=22, nullable=False)
    username = db.Column(db.String(100), nullable=False)
    encrypted_password = db.Column(db.String(255), nullable=False)
    backups = db.relationship('BackupFile', backref='device', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Device {self.name}>'

class BackupFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('device.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    display_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    filepath = db.Column(db.String(500), nullable=False)

    def __repr__(self):
        return f'<BackupFile {self.filename}>'

# --- Rotas da Aplicação ---
@app.route('/')
def index():
    devices = Device.query.all()
    return render_template('index.html', devices=devices)

@app.route('/add_device', methods=['GET', 'POST'])
def add_device():
    if request.method == 'POST':
        name = request.form['name']
        ip_address = request.form['ip_address']
        ssh_port = int(request.form['ssh_port'])
        username = request.form['username']
        password = request.form['password']

        if Device.query.filter_by(name=name).first():
            flash(f'Dispositivo com nome "{name}" já existe.', 'warning')
            return redirect(url_for('add_device'))
        
        try:
            encrypted_pass = encrypt_password(password)
        except Exception as e:
            flash(f'Erro ao criptografar senha (verifique se secret.key existe e é válida): {str(e)}', 'danger')
            app.logger.error(f"Erro de criptografia: {e}")
            return redirect(url_for('add_device'))

        new_device = Device(
            name=name, 
            ip_address=ip_address, 
            ssh_port=ssh_port,
            username=username,
            encrypted_password=encrypted_pass
        )
        try:
            db.session.add(new_device)
            db.session.commit()
            flash('Dispositivo adicionado com sucesso!', 'success')
            return redirect(url_for('index'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao adicionar dispositivo ao DB: {str(e)}', 'danger')
            app.logger.error(f"Erro DB ao adicionar dispositivo: {e}")

    return render_template('add_device.html')

@app.route('/device/<int:device_id>/backups')
def device_backups(device_id):
    device = Device.query.get_or_404(device_id)
    backups = BackupFile.query.filter_by(device_id=device.id).order_by(BackupFile.timestamp.desc()).all()
    return render_template('device_backups.html', device=device, backups=backups)

@app.route('/device/<int:device_id>/trigger_backup', methods=['POST'])
def trigger_backup(device_id):
    device = Device.query.get_or_404(device_id)
    
    device_backup_dir = os.path.join(BACKUP_DIR, str(device.id) + "_" + "".join(c if c.isalnum() else "_" for c in device.name) )
    if not os.path.exists(device_backup_dir):
        os.makedirs(device_backup_dir)

    now = datetime.datetime.now()
    timestamp_str = now.strftime("%Y%m%d_%H%M%S")
    
    base_filename_on_mt = f"mvp_auto_bkp_{timestamp_str}" # Nome unico no Mikrotik
    backup_filename_on_mt = f"{base_filename_on_mt}.backup"
    rsc_filename_on_mt = f"{base_filename_on_mt}.rsc"

    server_backup_filename = f"{''.join(c if c.isalnum() else '_' for c in device.name)}_{timestamp_str}.backup"
    server_rsc_filename = f"{''.join(c if c.isalnum() else '_' for c in device.name)}_{timestamp_str}.rsc"
    
    server_backup_filepath = os.path.join(device_backup_dir, server_backup_filename)
    server_rsc_filepath = os.path.join(device_backup_dir, server_rsc_filename)

    ssh = None
    sftp = None
    success_count = 0

    try:
        password = decrypt_password(device.encrypted_password)
        
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(device.ip_address, port=device.ssh_port, username=device.username, password=password, timeout=20, look_for_keys=False, allow_agent=False)
        sftp = ssh.open_sftp()

        # 1. Backup Binário (.backup)
        try:
            backup_command = f"/system backup save name={base_filename_on_mt} dont-encrypt=yes"
            stdin, stdout, stderr = ssh.exec_command(backup_command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                sftp.get(backup_filename_on_mt, server_backup_filepath)
                sftp.remove(backup_filename_on_mt)
                
                new_backup_entry = BackupFile(
                    device_id=device.id, filename=server_backup_filename, display_name=server_backup_filename,
                    file_type='backup', timestamp=now, filepath=server_backup_filepath
                )
                db.session.add(new_backup_entry)
                success_count += 1
                flash(f'Backup binário (.backup) de {device.name} criado!', 'success')
            else:
                err_msg = stderr.read().decode().strip() or "Erro desconhecido (sem output)"
                flash(f'Erro ao gerar .backup em {device.name}: {err_msg}', 'danger')
                app.logger.error(f"Erro backup binario {device.name}: {err_msg} (exit: {exit_status})")
        except Exception as e:
            flash(f'Falha no .backup para {device.name}: {str(e)}', 'danger')
            app.logger.error(f"Falha backup binario {device.name}: {e}")

        # 2. Exportação de Configuração (.rsc)
        try:
            export_command = f"/export file={base_filename_on_mt}" # .rsc é adicionado automaticamente
            stdin, stdout, stderr = ssh.exec_command(export_command)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                sftp.get(rsc_filename_on_mt, server_rsc_filepath) # Nome no MT já é .rsc
                sftp.remove(rsc_filename_on_mt)
                
                new_rsc_entry = BackupFile(
                    device_id=device.id, filename=server_rsc_filename, display_name=server_rsc_filename,
                    file_type='rsc', timestamp=now, filepath=server_rsc_filepath
                )
                db.session.add(new_rsc_entry)
                success_count += 1
                flash(f'Exportação (.rsc) de {device.name} criada!', 'success')
            else:
                err_msg = stderr.read().decode().strip() or "Erro desconhecido (sem output)"
                flash(f'Erro ao gerar .rsc em {device.name}: {err_msg}', 'danger')
                app.logger.error(f"Erro export .rsc {device.name}: {err_msg} (exit: {exit_status})")
        except Exception as e:
            flash(f'Falha na exportação (.rsc) para {device.name}: {str(e)}', 'danger')
            app.logger.error(f"Falha export .rsc {device.name}: {e}")

        if success_count > 0:
            db.session.commit()
        else:
            db.session.rollback()

    except paramiko.AuthenticationException:
        flash(f'Falha na autenticação com {device.name}. Verifique as credenciais.', 'danger')
        app.logger.error(f"Auth falhou para {device.name}")
    except paramiko.SSHException as ssh_ex:
        flash(f'Erro de SSH ao conectar com {device.name}: {str(ssh_ex)}', 'danger')
        app.logger.error(f"SSH erro para {device.name}: {ssh_ex}")
    except Exception as e:
        flash(f'Erro inesperado ao fazer backup de {device.name}: {str(e)}', 'danger')
        app.logger.error(f"Erro inesperado backup {device.name}: {e}")
        if 'db' in locals() and db.session.is_active: # Verifica se a sessão do db existe e está ativa
             db.session.rollback()
    finally:
        if sftp: sftp.close()
        if ssh: ssh.close()
            
    return redirect(url_for('device_backups', device_id=device_id))

@app.route('/download_backup/<int:backup_id>')
def download_backup(backup_id):
    backup_file_entry = BackupFile.query.get_or_404(backup_id)
    directory = os.path.dirname(backup_file_entry.filepath)
    filename = os.path.basename(backup_file_entry.filepath)
    try:
        return send_from_directory(directory, filename, as_attachment=True)
    except FileNotFoundError:
        flash('Arquivo de backup não encontrado no servidor.', 'danger')
        if backup_file_entry.device:
             return redirect(url_for('device_backups', device_id=backup_file_entry.device_id))
        return redirect(url_for('index'))

def create_db_and_key():
    """Função para ser chamada antes da primeira requisição para garantir DB e chave."""
    global cipher_suite
    if not os.path.exists(FERNET_KEY_FILE):
        print(f"Gerando novo arquivo {FERNET_KEY_FILE}...")
        key = Fernet.generate_key()
        with open(FERNET_KEY_FILE, "wb") as key_file:
            key_file.write(key)
        cipher_suite = Fernet(key) # Atualiza o cipher global
        print(f"{FERNET_KEY_FILE} gerado.")
    elif cipher_suite is None: # Se o arquivo existe mas o cipher não foi carregado
         with open(FERNET_KEY_FILE, "rb") as key_file:
            key = key_file.read()
         cipher_suite = Fernet(key)

    with app.app_context():
        db.create_all()
        print("Banco de dados verificado/criado.")

if __name__ == '__main__':
    create_db_and_key() # Garante que a chave e o DB existam ao iniciar
    app.run(debug=True, host='0.0.0.0', port=5001)
