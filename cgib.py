from flask import (
    Flask, render_template, request, redirect, url_for,
    session, send_from_directory, flash, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timezone
import os
import psycopg2
import logging

# --- Configuration des logs ---
logging.basicConfig(
    filename='cgib.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# --- Initialisation de l'application ---
app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:Verseaux69170@localhost/cgib'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Initialisation de Socket.IO
socketio = SocketIO(app, cors_allowed_origins="*", logger=True, engineio_logger=True)

if __name__ == "__main__":
    from flask_socketio import SocketIO
    socketio = SocketIO(app)
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)

# --- Modèles de base de données ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='bellboy')

class Vehicle(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    status = db.Column(db.String(20), nullable=False, default="Disponible")
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref='vehicles', lazy=True)

class VehicleLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    mileage = db.Column(db.Integer, nullable=False)
    reason = db.Column(db.String(255), nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    
    vehicle = db.relationship('Vehicle', backref='logs')
    user = db.relationship('User', backref='vehicle_logs')

class ShiftLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    duty_phone = db.Column(db.Integer, nullable=False)  # 1, 2, 3, 4, ou 5
    start_time = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    end_time = db.Column(db.DateTime, nullable=True)
    comment = db.Column(db.Text, nullable=True)
    
    user = db.relationship('User', backref=db.backref('shifts', lazy=True))
    
class Tasks(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime, nullable=True)
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    requester = db.relationship('User', foreign_keys=[requester_id], backref='tasks_requested')
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id], backref='tasks_assigned')
    task_type = db.Column(db.String(50), nullable=False)
    room_number = db.Column(db.String(10), nullable=True)
    status = db.Column(db.String(20), nullable=False, default="Attente")  # Attente, En cours, Terminé, Annulé
    archived = db.Column(db.Boolean, default=False)  # Pour archiver la tâche
    
    def __repr__(self):
        return f'<Task {self.id} - {self.status}>'

# --- Fonction utilitaire ---
def create_admin():
    existing_admin = User.query.filter_by(username='admin').first()
    if not existing_admin:
        if not User.query.filter_by(email='admin@cgib.com').first():
            hashed_pw = generate_password_hash('admin', method='pbkdf2:sha256')
            admin = User(username='admin', email='admin@cgib.com', password_hash=hashed_pw, role='admin')
            db.session.add(admin)
            db.session.commit()
            logging.info("Admin account created")
        else:
            logging.warning("L'email admin@cgib.com existe déjà. L'admin ne sera pas recréé.")
    else:
        logging.info("Admin account already exists")

# --- Routes ---

# ## Authentification et Dashboard
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            session['role'] = user.role
            session['username'] = user.username
            logging.info(f'User {username} logged in')
            return redirect(url_for('dashboard'))
        else:
            logging.warning(f'Failed login attempt for {username}')
            flash("Identifiants invalides, réessayez.", "danger")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    role = session['role']
    # Récupérer et supprimer le message temporaire après affichage
    shift_message = session.pop('shift_success', None)
    logging.info(f'User {session["user_id"]} accessed the dashboard')
    
    if role == 'admin':
        return render_template('admin_dashboard.html', shift_message=shift_message)
    else:
        return render_template('bellboy_dashboard.html', shift_message=shift_message)

@app.route('/logout')
def logout():
    logging.info(f'User {session.get("user_id")} logged out')
    session.pop('user_id', None)
    session.pop('role', None)
    session.pop('username', None)
    return redirect(url_for('login'))

# ## Gestion des utilisateurs (Admin)
@app.route('/admin/users', methods=['GET', 'POST'])
def manage_users():
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."

    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form.get('role')
        
        # Vérification du rôle sélectionné
        valid_roles = ["bellboy", "coordinator", "admin"]
        if role not in valid_roles:
            flash("Rôle invalide.", "danger")
            logging.warning(f"Tentative de création d'un utilisateur avec un rôle invalide : {role}")
            return redirect(url_for('manage_users'))
        
        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        print(f"🚀 Création de l'utilisateur : {username}, Email: {email}, Role: {role}")  # DEBUG
        
        new_user = User(username=username, email=email, password_hash=hashed_pw, role=role)
        db.session.add(new_user)
        db.session.commit()
        
        created_user = User.query.filter_by(username=username).first()
        print(f"🟢 Utilisateur créé en base : {created_user.username}, Role: {created_user.role}")  # DEBUG
        
        logging.info(f'Admin created user {username} with email {email} and role {role}')
        flash(f"Utilisateur {username} créé avec succès en tant que {role}.", "success")
    
    users = User.query.all()
    return render_template('users.html', users=users)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."
    
    user = db.session.get(User, user_id)
    if request.method == 'POST':
        user.username = request.form['username']
        user.email = request.form['email']
        if request.form['password']:
            user.password_hash = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        user.role = request.form['role']
        db.session.commit()
        logging.info(f'Admin edited user {user.username} with email {user.email}')
        return redirect(url_for('manage_users'))
    return render_template('edit_user.html', user=user)

@app.route('/admin/delete_user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({"success": False, "error": "Accès refusé."})

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"success": False, "error": "Utilisateur introuvable."})

    if user.role == "admin":
        return jsonify({"success": False, "error": "Impossible de supprimer un administrateur."})

    try:
        # Supprimer les tâches créées et celles assignées à l'utilisateur
        Tasks.query.filter_by(requester_id=user.id).delete()
        Tasks.query.filter_by(assigned_to_id=user.id).update({"assigned_to_id": None})
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True, "message": "Utilisateur supprimé avec succès."})
    except Exception as e:
        db.session.rollback()
        print(f"❌ ERREUR : {e}")  # DEBUG
        return jsonify({"success": False, "error": "Erreur interne du serveur"})

# ## Gestion des fichiers BOD
@app.route('/admin/upload', methods=['GET', 'POST'])
def upload_bod():
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."
    
    if request.method == 'POST':
        file = request.files['file']
        if file.filename.endswith('.pdf'):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            logging.info(f'BOD uploaded: {filename} by user {session["user_id"]}')
            flash("Fichier uploadé avec succès !", "success")
            return redirect(url_for('view_bod'))
        flash("Seuls les fichiers PDF sont acceptés.", "danger")
    
    return render_template('upload.html')

@app.route('/bod')
def view_bod():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    files = os.listdir(app.config['UPLOAD_FOLDER'])
    logging.info(f'User {session["user_id"]} accessed the BOD list')
    return render_template('bod.html', files=files)

@app.route('/bod/<filename>')
def download_bod(filename):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/bod/delete/<filename>')
def delete_bod(filename):
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash("Fichier supprimé avec succès.", "success")
    else:
        flash("Fichier introuvable.", "danger")
    return redirect(url_for('view_bod'))

@app.route('/bod/confirm_delete/<filename>', methods=['GET', 'POST'])
def confirm_delete_bod(filename):
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."
    
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        logging.info(f'Admin deleted BOD file: {filename}')
        flash("Fichier supprimé avec succès.", "success")
    return redirect(url_for('view_bod'))

# ## Gestion des tâches
@app.route('/tasks')
def task_list():
    if 'user_id' not in session:
        flash("Veuillez vous connecter.", "danger")
        return redirect(url_for('login'))
    
    tasks = Tasks.query.filter_by(archived=False).order_by(Tasks.created_at.desc()).all()
    return render_template('tasks.html', tasks=tasks)

@app.route('/tasks/add', methods=['GET', 'POST'])
def add_task():
    if 'user_id' not in session or session['role'] not in ['admin', 'coordinator']:
        flash("Accès refusé.", "danger")
        return redirect(url_for('task_list'))
    
    task_type = request.form.get('task_type')
    room_number = request.form.get('room_number')
    if task_type not in ["Luggage PU", "Luggage Drop", "LaPoste PU", "LaPost Drop", "Car PU"]:
        flash("Type de tâche invalide.", "danger")
        return redirect(url_for('task_list'))
    
    new_task = Tasks(
        requester_id=session['user_id'],
        task_type=task_type,
        room_number=room_number if room_number else None,
        status="Attente"
    )
    db.session.add(new_task)
    db.session.commit()
    
    socketio.emit('update_tasks', {'action': 'add'})
    flash("Tâche ajoutée avec succès.", "success")
    return redirect(url_for('task_list'))

@app.route('/tasks/take/<int:task_id>', methods=['GET', 'POST'])
def take_task(task_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Vous devez être connecté."})
    
    try:
        task = db.session.get(Tasks, task_id)
        if not task:
            return jsonify({"success": False, "error": "Tâche introuvable."})
        if task.status != "Attente":
            return jsonify({"success": False, "error": "Cette tâche n'est pas disponible."})
        
        user_id = session['user_id']
        user_role = session['role']
        if user_role not in ['bellboy', 'coordinator', 'admin']:
            return jsonify({"success": False, "error": "Vous n'êtes pas autorisé à prendre cette tâche."})
        
        task.assigned_to_id = user_id
        task.status = "En cours"
        db.session.commit()
        socketio.emit('update_tasks', {'action': 'update'})
        return jsonify({"success": True, "message": "Tâche prise avec succès !"})
    except Exception as e:
        print(f"❌ ERREUR : {str(e)}")
        return jsonify({"success": False, "error": "Erreur interne du serveur"})

@app.route('/tasks/complete/<int:task_id>')
def complete_task(task_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    task = Tasks.query.get(task_id)
    if not task or task.status != "En cours" or task.assigned_to_id != session['user_id']:
        flash("Vous ne pouvez pas terminer cette tâche.", "danger")
        return redirect(url_for('task_list'))
    
    task.status = "Terminé"
    task.completed_at = datetime.now(timezone.utc)
    db.session.commit()
    socketio.emit('update_tasks', {'action': 'update'})
    flash("Tâche terminée.", "success")
    return redirect(url_for('task_list'))

@app.route('/tasks/cancel/<int:task_id>')
def cancel_task(task_id):
    if 'user_id' not in session:
        flash("Accès refusé.", "danger")
        return redirect(url_for('task_list'))
    
    task = Tasks.query.get(task_id)
    if not task:
        flash("Tâche introuvable.", "danger")
        return redirect(url_for('task_list'))
    
    if session['role'] != 'admin' and task.assigned_to_id != session['user_id']:
        flash("Vous n'avez pas l'autorisation d'annuler cette tâche.", "danger")
        return redirect(url_for('task_list'))
    
    task.status = "Annulé"
    db.session.commit()
    socketio.emit('update_tasks', {'action': 'update'})
    flash("Tâche annulée.", "info")
    return redirect(url_for('task_list'))

@app.route('/tasks/logs')
def tasks_logs():
    if 'user_id' not in session or session['role'] != 'admin':
        flash("Accès refusé.", "danger")
        return redirect(url_for('task_list'))
    
    archived_tasks = Tasks.query.filter_by(archived=True).order_by(Tasks.completed_at.desc()).all()
    return render_template('tasks_logs.html', tasks=archived_tasks)

@app.route('/tasks/archive/<int:task_id>', methods=['GET', 'POST'])
def archive_task(task_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash("Accès refusé.", "danger")
        return redirect(url_for('task_list'))
    
    task = Tasks.query.get(task_id)
    if not task:
        flash("Tâche introuvable.", "danger")
        return redirect(url_for('task_list'))
    
    if task.status not in ["Terminé", "Annulé"]:
        flash("Seules les tâches terminées ou annulées peuvent être archivées.", "danger")
        return redirect(url_for('task_list'))
    
    task.archived = True
    db.session.commit()
    socketio.emit('update_tasks', {'action': 'update'})
    flash("Tâche archivée avec succès.", "info")
    return redirect(url_for('task_list'))

@app.route('/tasks/delete/<int:task_id>', methods=['GET', 'POST'])
def delete_task(task_id):
    if 'user_id' not in session or session['role'] != 'admin':
        flash("Accès refusé.", "danger")
        return redirect(url_for('tasks_logs'))
    
    task = Tasks.query.get(task_id)
    if not task:
        flash("Tâche introuvable.", "danger")
        return redirect(url_for('tasks_logs'))
    
    if not task.archived:
        flash("Seules les tâches archivées peuvent être supprimées.", "danger")
        return redirect(url_for('tasks_logs'))
    
    db.session.delete(task)
    db.session.commit()
    flash("Tâche supprimée définitivement.", "danger")
    return redirect(url_for('tasks_logs'))

# ## Gestion des shifts
@app.route('/shift/start', methods=['GET', 'POST'])
def start_shift():
    if 'user_id' not in session or session['role'] != 'bellboy':
        return redirect(url_for('login'))
    
    active_shift = ShiftLog.query.filter_by(user_id=session['user_id'], end_time=None).first()
    if active_shift:
        flash("Vous avez déjà un shift en cours.", "warning")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        duty_phone = request.form.get('duty_phone')
        if not duty_phone or duty_phone not in ['1', '2', '3', '4', '5']:
            flash("Veuillez sélectionner un numéro de duty phone valide.", "danger")
            return redirect(url_for('start_shift'))
        
        new_shift = ShiftLog(user_id=session['user_id'], duty_phone=int(duty_phone))
        db.session.add(new_shift)
        db.session.commit()
        
        # Stocker le message temporairement dans la session
        session['shift_success'] = "Shift démarré avec succès !"
        return redirect(url_for('dashboard'))
    
    return render_template('start_shift.html')

@app.route('/shift/end', methods=['GET', 'POST'])
def end_shift():
    if 'user_id' not in session or session['role'] != 'bellboy':
        return redirect(url_for('login'))
    
    active_shift = ShiftLog.query.filter_by(user_id=session['user_id'], end_time=None).first()
    if not active_shift:
        flash("Vous n'avez pas de shift en cours.", "warning")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        comment = request.form.get('comment')
        active_shift.end_time = datetime.now(timezone.utc)
        active_shift.comment = comment
        db.session.commit()
        flash("Shift terminé. Vous êtes maintenant déconnecté.", "success")
        return redirect(url_for('logout'))
    
    return render_template('shift_end.html', shift=active_shift)

@app.route('/shift', methods=['GET', 'POST'])
def shift():
    if 'user_id' not in session or session['role'] != 'bellboy':
        return redirect(url_for('login'))
    
    active_shift = ShiftLog.query.filter_by(user_id=session['user_id'], end_time=None).first()
    return render_template('active_shift.html', active_shift=active_shift)

@app.route('/admin/shifts')
def admin_shift_logs():
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."
    
    shifts = db.session.query(
        ShiftLog.id,
        User.username.label("user_name"),
        ShiftLog.duty_phone,
        ShiftLog.start_time,
        ShiftLog.end_time,
        ShiftLog.comment
    ).join(User, User.id == ShiftLog.user_id).order_by(ShiftLog.start_time.desc()).all()
    
    return render_template('admin_shift_logs.html', shifts=shifts)

# ## Gestion des véhicules
@app.route('/cfu')
def cfu():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    vehicles = db.session.query(
        Vehicle.id,
        Vehicle.name,
        Vehicle.status,
        Vehicle.user_id,
        User.username.label("user_name")
    ).outerjoin(User, Vehicle.user_id == User.id).all()
    
    return render_template('cfu.html', vehicles=vehicles)

@app.route('/cfu/start/<int:vehicle_id>', methods=['GET', 'POST'])
def start_vehicle_use(vehicle_id):
    if 'user_id' not in session:
        return jsonify({"success": False, "error": "Vous devez être connecté."})
    
    user_id = session["user_id"]
    user = db.session.get(User, user_id)
    username = user.username if user else "Utilisateur inconnu"
    
    vehicle = db.session.get(Vehicle, vehicle_id)
    if not vehicle:
        return jsonify({"success": False, "error": "Véhicule introuvable."})
    if vehicle.status == "En cours":
        return jsonify({"success": False, "error": "Ce véhicule est déjà utilisé."})
    
    # Vérifier s'il y a un ancien log non clôturé
    old_log = VehicleLog.query.filter_by(vehicle_id=vehicle.id, user_id=user_id, end_time=None).first()
    if old_log:
        old_log.end_time = datetime.utcnow()
        db.session.commit()
    
    vehicle.status = "En cours"
    vehicle.user_id = user_id
    
    new_log = VehicleLog(
        vehicle_id=vehicle.id,
        user_id=user_id,
        mileage=0,
        reason="Départ",
        start_time=datetime.utcnow()
    )
    db.session.add(new_log)
    db.session.commit()
    
    socketio.emit('vehicle_update', {
        'vehicle_id': vehicle.id,
        'status': "En cours",
        'user_name': username,
        'user_id': user_id,
        'vehicle_name': vehicle.name
    })
    
    return jsonify({"success": True, "message": f"🚗 {vehicle.name} est maintenant En cours !"})

@app.route('/vehicles/release/<int:vehicle_id>', methods=['POST'])
def release_vehicle(vehicle_id):
    if 'user_id' not in session:
        print("🚨 ERREUR : Utilisateur non connecté !")
        return jsonify({"success": False, "error": "Vous devez être connecté."})
    
    user_id = session['user_id']
    user_role = session['role']
    user = db.session.get(User, user_id)
    username = user.username if user else "Utilisateur inconnu"
    
    mileage = request.form.get("mileage")
    reason = request.form.get("reason")
    
    print(f"🔍 Tentative de libération du véhicule {vehicle_id} par {username} (ID: {user_id}, Role: {user_role})")
    if not mileage or not reason:
        print("🚨 ERREUR : Kilométrage ou raison manquant !")
        return jsonify({"success": False, "error": "Le kilométrage et la raison sont obligatoires."})
    
    vehicle = db.session.get(Vehicle, vehicle_id)
    if not vehicle:
        print("🚨 ERREUR : Véhicule introuvable !")
        return jsonify({"success": False, "error": "Véhicule introuvable."})
    if vehicle.status != "En cours":
        print("🚨 ERREUR : Le véhicule n'est pas en cours d'utilisation !")
        return jsonify({"success": False, "error": "Ce véhicule n'est pas en cours d'utilisation."})
    
    log = VehicleLog.query.filter_by(vehicle_id=vehicle.id, end_time=None).first()
    if not log:
        print("🚨 ERREUR : Aucune session active trouvée pour ce véhicule !")
        return jsonify({"success": False, "error": "Aucune session active trouvée."})
    if log.user_id != user_id and user_role != 'admin':
        print("🚨 ERREUR : L'utilisateur n'a pas l'autorisation !")
        return jsonify({"success": False, "error": "Vous n'avez pas l'autorisation de libérer ce véhicule."})
    
    log.end_time = datetime.utcnow()
    log.mileage = int(mileage)
    log.reason = reason
    vehicle.status = "Disponible"
    vehicle.user_id = None
    
    db.session.commit()
    print(f"✅ SUCCÈS : Véhicule {vehicle.name} libéré par {username} !")
    
    socketio.emit('vehicle_update', {
        'vehicle_id': vehicle.id,
        'status': "Disponible",
        'user_name': username,
        'vehicle_name': vehicle.name,
        'mileage': mileage,
        'reason': reason
    })
    
    return jsonify({"success": True, "message": f"🚗 {vehicle.name} est maintenant Disponible !"})

@app.route('/cfu/end/<int:vehicle_id>')
def end_vehicle_use(vehicle_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    vehicle = db.session.get(Vehicle, vehicle_id)
    if not vehicle or vehicle.status != "En cours":
        flash("Ce véhicule n'est pas en cours d'utilisation.", "danger")
        return redirect(url_for('cfu'))
    
    log = VehicleLog.query.filter_by(vehicle_id=vehicle.id, end_time=None).first()
    if log:
        log.end_time = datetime.now(timezone.utc)
    
    vehicle.status = "Disponible"
    vehicle.user_id = None
    db.session.commit()
    
    socketio.emit('vehicle_update', {
        'vehicle_name': vehicle.name,
        'status': "Disponible"
    })
    
    flash(f"Vous avez terminé l'utilisation de {vehicle.name}.", "success")
    return redirect(url_for('cfu'))

@app.route('/admin/delete_vehicle_log/<int:log_id>', methods=['GET', 'POST'])
def delete_vehicle_log(log_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return jsonify({"success": False, "error": "Accès refusé."})
    
    log = db.session.get(VehicleLog, log_id)
    if not log:
        return jsonify({"success": False, "error": "Entrée introuvable."})
    
    db.session.delete(log)
    db.session.commit()
    flash("Entrée supprimée avec succès.", "success")
    return jsonify({"success": True})

@app.route('/admin/vehicles', methods=['GET', 'POST'])
def manage_vehicles():
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."
    
    if request.method == 'POST':
        name = request.form['name']
        new_vehicle = Vehicle(name=name)
        db.session.add(new_vehicle)
        db.session.commit()
        flash(f"Véhicule {name} ajouté.", "success")
    
    vehicles = Vehicle.query.all()
    return render_template('admin_vehicles.html', vehicles=vehicles)

@app.route('/admin/vehicle_logs')
def vehicle_logs():
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."
    
    logs = db.session.query(
        VehicleLog.id,
        Vehicle.name.label("vehicle_name"),
        User.username.label("user_name"),
        VehicleLog.start_time,
        VehicleLog.end_time,
        VehicleLog.mileage,
        VehicleLog.reason
    ).join(Vehicle, Vehicle.id == VehicleLog.vehicle_id) \
     .join(User, User.id == VehicleLog.user_id) \
     .order_by(VehicleLog.start_time.desc()).all()
    
    return render_template('admin_vehicle_logs.html', logs=logs)

@app.route('/admin/edit_vehicle/<int:vehicle_id>', methods=['GET', 'POST'])
def edit_vehicle(vehicle_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."
    
    vehicle = db.session.get(Vehicle, vehicle_id)
    if not vehicle:
        flash("Véhicule introuvable.", "danger")
        return redirect(url_for('manage_vehicles'))
    
    if request.method == 'POST':
        new_name = request.form['name']
        if new_name.strip() == "":
            flash("Le nom du véhicule ne peut pas être vide.", "danger")
        else:
            vehicle.name = new_name
            db.session.commit()
            flash(f"Véhicule renommé en {new_name}.", "success")
            return redirect(url_for('manage_vehicles'))
    
    return render_template('edit_vehicle.html', vehicle=vehicle)

@app.route('/admin/delete_vehicle/<int:vehicle_id>')
def delete_vehicle(vehicle_id):
    if 'user_id' not in session or session['role'] != 'admin':
        return "Accès refusé."
    
    vehicle = db.session.get(Vehicle, vehicle_id)
    if not vehicle:
        flash("Véhicule introuvable.", "danger")
        return redirect(url_for('manage_vehicles'))
    
    # Supprimer les logs associés avant de supprimer le véhicule
    logs = VehicleLog.query.filter_by(vehicle_id=vehicle.id).all()
    for log in logs:
        db.session.delete(log)
    db.session.commit()
    
    db.session.delete(vehicle)
    db.session.commit()
    
    flash(f"Véhicule {vehicle.name} supprimé avec succès.", "danger")
    return redirect(url_for('manage_vehicles'))

# --- Gestion des erreurs ---
@app.errorhandler(404)
def not_found_error(error):
    return jsonify({"success": False, "error": "Route non trouvée"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"success": False, "error": "Erreur interne du serveur"}), 500