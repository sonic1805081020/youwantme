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

# Extensions vidéo et photo autorisées
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv', 'webm', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'}

# Créer les dossiers uploads s'ils n'existent pas
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'photos'), exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_image(filename):
    image_extensions = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in image_extensions

def is_video(filename):
    video_extensions = {'mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv', 'webm'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in video_extensions

def upload_to_cloudinary(file, file_type):
    """Upload un fichier vers Cloudinary"""
    try:
        if file_type == 'photo':
            # Upload d'image
            result = cloudinary.uploader.upload(
                file,
                resource_type="image",
                folder="mes_medias/photos",
                use_filename=True,
                unique_filename=True,
                quality="auto",
                fetch_format="auto"
            )
        else:
            # Upload de vidéo
            result = cloudinary.uploader.upload(
                file,
                resource_type="video",
                folder="mes_medias/videos",
                use_filename=True,
                unique_filename=True
            )
        
        return {
            'success': True,
            'url': result['secure_url'],
            'public_id': result['public_id'],
            'duration': result.get('duration', 0),
            'format': result.get('format', ''),
            'size': result.get('bytes', 0)
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e)
        }

def delete_from_cloudinary(public_id, file_type):
    """Supprimer un fichier de Cloudinary"""
    try:
        resource_type = "image" if file_type == 'photo' else "video"
        result = cloudinary.uploader.destroy(public_id, resource_type=resource_type)
        return result.get('result') == 'ok'
    except Exception as e:
        print(f"Erreur suppression Cloudinary: {e}")
        return False

def is_image(filename):
    image_extensions = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in image_extensions

def is_video(filename):
    video_extensions = {'mp4', 'avi', 'mov', 'mkv', 'wmv', 'flv', 'webm'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in video_extensions

def get_video_duration(file_path):
    """Obtenir la durée d'une vidéo avec ffprobe (optimisé)"""
    try:
        cmd = [
            'ffprobe', '-v', 'quiet', '-print_format', 'json', 
            '-show_format', '-select_streams', 'v:0', file_path
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            duration = float(data['format']['duration'])
            return duration
    except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError, KeyError):
        pass
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
        # Créer la nouvelle table avec support des liens et photos
        c.execute('''CREATE TABLE videos
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      filename TEXT,
                      original_name TEXT,
                      title TEXT NOT NULL,
                      description TEXT,
                      duration REAL,
                      upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                      user_id INTEGER,
                      media_type TEXT DEFAULT 'upload',
                      external_url TEXT,
                      file_type TEXT DEFAULT 'video',
                      FOREIGN KEY (user_id) REFERENCES users (id))''')
    else:
        # Vérifier si la colonne user_id existe
        c.execute("PRAGMA table_info(videos)")
        columns = [column[1] for column in c.fetchall()]
        
        if 'user_id' not in columns:
            # Ajouter les nouvelles colonnes
            c.execute('ALTER TABLE videos ADD COLUMN user_id INTEGER')
            c.execute('ALTER TABLE videos ADD COLUMN media_type TEXT DEFAULT "upload"')
            c.execute('ALTER TABLE videos ADD COLUMN external_url TEXT')
            c.execute('ALTER TABLE videos ADD COLUMN file_type TEXT DEFAULT "video"')
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
            
            # Sauvegarder le fichier
            file.save(filepath)
            
            # Obtenir la durée de la vidéo (avec timeout)
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
    """Servir les fichiers vidéo avec support du streaming"""
    # Vérifier que le fichier appartient à l'utilisateur connecté
    conn = sqlite3.connect('videos.db')
    c = conn.cursor()
    c.execute('SELECT id FROM videos WHERE filename = ? AND user_id = ?', (filename, session['user_id']))
    video = c.fetchone()
    conn.close()
    
    if not video:
        flash('Accès non autorisé', 'error')
        return redirect(url_for('index'))
    
    def generate():
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        if not os.path.exists(filepath):
            return
            
        with open(filepath, 'rb') as f:
            data = f.read(1024 * 1024)  # Lire par chunks de 1MB
            while data:
                yield data
                data = f.read(1024 * 1024)
    
    # Support du range request pour le streaming
    range_header = request.headers.get('Range', None)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    if not os.path.exists(filepath):
        return "Fichier non trouvé", 404
    
    file_size = os.path.getsize(filepath)
    
    if range_header:
        byte_start = 0
        byte_end = file_size - 1
        
        range_match = range_header.replace('bytes=', '').split('-')
        if range_match[0]:
            byte_start = int(range_match[0])
        if range_match[1]:
            byte_end = int(range_match[1])
        
        content_length = byte_end - byte_start + 1
        
        def generate_range():
            with open(filepath, 'rb') as f:
                f.seek(byte_start)
                remaining = content_length
                while remaining:
                    chunk_size = min(1024 * 1024, remaining)  # 1MB chunks
                    data = f.read(chunk_size)
                    if not data:
                        break
                    remaining -= len(data)
                    yield data
        
        response = app.response_class(
            generate_range(),
            206,  # Partial Content
            headers={
                'Content-Range': f'bytes {byte_start}-{byte_end}/{file_size}',
                'Accept-Ranges': 'bytes',
                'Content-Length': str(content_length),
                'Content-Type': 'video/mp4',
            }
        )
        return response
    else:
        return send_from_directory(
            app.config['UPLOAD_FOLDER'], 
            filename,
            mimetype='video/mp4'
        )

@app.route('/download/<int:media_id>')
@login_required
def download_media(media_id):
    """Télécharger un média"""
    conn = sqlite3.connect('videos.db')
    c = conn.cursor()
    c.execute('SELECT filename, original_name, file_type FROM videos WHERE id = ? AND user_id = ?', (media_id, session['user_id']))
    media = c.fetchone()
    conn.close()
    
    if not media or not media[0]:  # Pas de fichier local
        flash('Média non trouvé ou accès non autorisé', 'error')
        return redirect(url_for('index'))
    
    if media[2] == 'photo':
        folder = os.path.join(app.config['UPLOAD_FOLDER'], 'photos')
    else:
        folder = app.config['UPLOAD_FOLDER']
    
    return send_from_directory(
        folder, 
        media[0], 
        as_attachment=True, 
        download_name=media[1]
    )

@app.route('/delete/<int:media_id>')
@login_required
def delete_media(media_id):
    """Supprimer un média"""
    conn = sqlite3.connect('videos.db')
    c = conn.cursor()
    c.execute('SELECT filename, file_type FROM videos WHERE id = ? AND user_id = ?', (media_id, session['user_id']))
    media = c.fetchone()
    
    if media:
        # Supprimer le fichier s'il existe
        if media[0]:  # filename existe
            if media[1] == 'photo':
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], 'photos', media[0])
            else:
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], media[0])
            
            if os.path.exists(filepath):
                os.remove(filepath)
        
        # Supprimer de la base de données
        c.execute('DELETE FROM videos WHERE id = ? AND user_id = ?', (media_id, session['user_id']))
        conn.commit()
        flash('Média supprimé avec succès', 'success')
    else:
        flash('Média non trouvé ou accès non autorisé', 'error')
    
    conn.close()
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)