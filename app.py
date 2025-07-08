from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import os
import sqlite3
from datetime import datetime
import subprocess
import json
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Extensions vidéo autorisées
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv', 'webm'}

# Créer le dossier uploads s'il n'existe pas
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_video_duration(file_path):
    """Obtenir la durée d'une vidéo avec ffprobe"""
    try:
        cmd = [
            'ffprobe', '-v', 'quiet', '-print_format', 'json', 
            '-show_format', file_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        data = json.loads(result.stdout)
        duration = float(data['format']['duration'])
        return duration
    except:
        return None

def init_db():
    """Initialiser la base de données"""
    conn = sqlite3.connect('videos.db')
    c = conn.cursor()
    
    # Table des utilisateurs (créer en premier)
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password_hash TEXT NOT NULL,
                  created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Créer le compte par défaut s'il n'existe pas
    c.execute('SELECT id FROM users WHERE username = ?', ('youwantme',))
    default_user = c.fetchone()
    if not default_user:
        password_hash = generate_password_hash('lyublyubaby081020!')
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                  ('youwantme', password_hash))
        c.execute('SELECT id FROM users WHERE username = ?', ('youwantme',))
        default_user = c.fetchone()
    
    default_user_id = default_user[0]
    
    # Vérifier si la table videos existe
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='videos'")
    table_exists = c.fetchone()
    
    if not table_exists:
        # Créer la nouvelle table avec user_id
        c.execute('''CREATE TABLE videos
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      filename TEXT NOT NULL,
                      original_name TEXT NOT NULL,
                      title TEXT NOT NULL,
                      description TEXT,
                      duration REAL,
                      upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      user_id INTEGER,
                      FOREIGN KEY (user_id) REFERENCES users (id))''')
    else:
        # Vérifier si la colonne user_id existe
        c.execute("PRAGMA table_info(videos)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'user_id' not in columns:
            # Ajouter la colonne user_id aux vidéos existantes
            c.execute('ALTER TABLE videos ADD COLUMN user_id INTEGER')
            # Assigner toutes les vidéos existantes à l'utilisateur par défaut
            c.execute('UPDATE videos SET user_id = ? WHERE user_id IS NULL', (default_user_id,))
    
    conn.commit()
    conn.close()

def login_required(f):
    """Décorateur pour protéger les routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Vous devez être connecté pour accéder à cette page', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Nom d\'utilisateur et mot de passe requis', 'error')
            return redirect(request.url)
        
        conn = sqlite3.connect('videos.db')
        c = conn.cursor()
        c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            session['username'] = username
            flash('Connexion réussie !', 'success')
            return redirect(url_for('index'))
        else:
            flash('Nom d\'utilisateur ou mot de passe incorrect', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Page d'inscription"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not username or not password or not confirm_password:
            flash('Tous les champs sont requis', 'error')
            return redirect(request.url)
        
        if password != confirm_password:
            flash('Les mots de passe ne correspondent pas', 'error')
            return redirect(request.url)
        
        if len(password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères', 'error')
            return redirect(request.url)
        
        conn = sqlite3.connect('videos.db')
        c = conn.cursor()
        
        # Vérifier si l'utilisateur existe déjà
        c.execute('SELECT id FROM users WHERE username = ?', (username,))
        if c.fetchone():
            flash('Ce nom d\'utilisateur existe déjà', 'error')
            conn.close()
            return redirect(request.url)
        
        # Créer le nouvel utilisateur
        password_hash = generate_password_hash(password)
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                  (username, password_hash))
        conn.commit()
        conn.close()
        
        flash('Compte créé avec succès ! Vous pouvez maintenant vous connecter.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Déconnexion"""
    session.clear()
    flash('Déconnexion réussie', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    """Page d'accueil avec liste des vidéos"""
    conn = sqlite3.connect('videos.db')
    c = conn.cursor()
    # Afficher seulement les vidéos de l'utilisateur connecté
    c.execute('SELECT * FROM videos WHERE user_id = ? ORDER BY upload_date DESC', (session['user_id'],))
    videos = c.fetchall()
    conn.close()
    return render_template('index.html', videos=videos)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_video():
    """Page d'upload de vidéos"""
    if request.method == 'POST':
        # Vérifier si un fichier a été sélectionné
        if 'video' not in request.files:
            flash('Aucun fichier sélectionné', 'error')
            return redirect(request.url)
        
        file = request.files['video']
        title = request.form.get('title', '')
        description = request.form.get('description', '')
        
        if file.filename == '':
            flash('Aucun fichier sélectionné', 'error')
            return redirect(request.url)
        
        if not title:
            flash('Le titre est requis', 'error')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # Ajouter timestamp pour éviter les conflits
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_')
            filename = timestamp + filename
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            # Sauvegarder temporairement pour vérifier la durée
            file.save(filepath)
            
            # Obtenir la durée de la vidéo
            duration = get_video_duration(filepath)
            if duration is None:
                duration = 0  # Valeur par défaut si impossible de déterminer
            
            # Sauvegarder en base de données avec l'ID utilisateur
            conn = sqlite3.connect('videos.db')
            c = conn.cursor()
            c.execute('''INSERT INTO videos (filename, original_name, title, description, duration, user_id)
                         VALUES (?, ?, ?, ?, ?, ?)''',
                      (filename, file.filename, title, description, duration, session['user_id']))
            conn.commit()
            conn.close()
            
            flash('Vidéo uploadée avec succès!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Type de fichier non autorisé', 'error')
    
    return render_template('upload.html')

@app.route('/watch/<int:video_id>')
@login_required
def watch_video(video_id):
    """Page de lecture d'une vidéo"""
    conn = sqlite3.connect('videos.db')
    c = conn.cursor()
    # Vérifier que la vidéo appartient à l'utilisateur connecté
    c.execute('SELECT * FROM videos WHERE id = ? AND user_id = ?', (video_id, session['user_id']))
    video = c.fetchone()
    conn.close()
    
    if not video:
        flash('Vidéo non trouvée ou accès non autorisé', 'error')
        return redirect(url_for('index'))
    
    return render_template('watch.html', video=video)

@app.route('/video/<filename>')
@login_required
def serve_video(filename):
    """Servir les fichiers vidéo"""
    # Vérifier que le fichier appartient à l'utilisateur connecté
    conn = sqlite3.connect('videos.db')
    c = conn.cursor()
    c.execute('SELECT id FROM videos WHERE filename = ? AND user_id = ?', (filename, session['user_id']))
    video = c.fetchone()
    conn.close()
    
    if not video:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('index'))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/download/<int:video_id>')
@login_required
def download_video(video_id):
    """Télécharger une vidéo"""
    conn = sqlite3.connect('videos.db')
    c = conn.cursor()
    # Vérifier que la vidéo appartient à l'utilisateur connecté
    c.execute('SELECT filename, original_name FROM videos WHERE id = ? AND user_id = ?', (video_id, session['user_id']))
    video = c.fetchone()
    conn.close()
    
    if not video:
        flash('Vidéo non trouvée ou accès non autorisé', 'error')
        return redirect(url_for('index'))
    
    return send_from_directory(
        app.config['UPLOAD_FOLDER'], 
        video[0], 
        as_attachment=True, 
        download_name=video[1]
    )

@app.route('/delete/<int:video_id>')
@login_required
def delete_video(video_id):
    """Supprimer une vidéo"""
    conn = sqlite3.connect('videos.db')
    c = conn.cursor()
    # Vérifier que la vidéo appartient à l'utilisateur connecté
    c.execute('SELECT filename FROM videos WHERE id = ? AND user_id = ?', (video_id, session['user_id']))
    video = c.fetchone()
    
    if video:
        # Supprimer le fichier
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], video[0])
        if os.path.exists(filepath):
            os.remove(filepath)
        
        # Supprimer de la base de données
        c.execute('DELETE FROM videos WHERE id = ? AND user_id = ?', (video_id, session['user_id']))
        conn.commit()
        flash('Vidéo supprimée avec succès', 'success')
    else:
        flash('Vidéo non trouvée ou accès non autorisé', 'error')
    
    conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)