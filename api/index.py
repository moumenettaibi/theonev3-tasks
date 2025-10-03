# api/index.py

import os
import json
import uuid
import atexit
import re
import requests
import wikipedia
import psycopg2
import psycopg2.extras
from psycopg2.pool import SimpleConnectionPool
from contextlib import contextmanager
from datetime import timedelta, date # --- MODIFIED: Imported timedelta

from flask import Flask, render_template, request, jsonify, session # --- MODIFIED: Imported session
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash

from dotenv import load_dotenv
load_dotenv()

# --- App & SocketIO Setup ---
app = Flask(__name__, template_folder='../templates', static_folder='../static')

# --- MODIFIED: CRITICAL FOR PERSISTENT LOGINS ACROSS DEPLOYMENTS ---
# You MUST set a strong, permanent secret key in your deployment environment (e.g., Vercel, Heroku).
# If this key changes, all users will be logged out.
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY:
    print("WARNING: FLASK_SECRET_KEY environment variable not set. Using a weak, temporary key for development.")
    print("         For production, you MUST set a persistent FLASK_SECRET_KEY.")
    SECRET_KEY = 'a-strong-dev-secret-key-that-is-not-so-secret'
app.secret_key = SECRET_KEY

# --- MODIFIED: Set the session to last for one year ---
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)


socketio = SocketIO(app)

# --- Database Connection Pool ---
try:
    pool = SimpleConnectionPool(
        minconn=1,
        maxconn=10,
        dsn=os.environ['POSTGRES_URL']
    )
except psycopg2.OperationalError as e:
    raise RuntimeError(f"Could not connect to the database. Check your POSTGRES_URL. Error: {e}")

@atexit.register
def close_pool():
    if pool:
        pool.closeall()
        print("Database connection pool closed.")

@contextmanager
def get_db_connection():
    conn = pool.getconn()
    try:
        yield conn
    finally:
        pool.putconn(conn)

# --- Database Schema Migration ---
def run_migrations():
    """Checks for and applies necessary database schema changes."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            print("Checking database schema...")

            # Add is_one_time column if it doesn't exist
            cur.execute("""
                SELECT 1 FROM information_schema.columns
                WHERE table_name='tasks' AND column_name='is_one_time';
            """)
            if cur.fetchone() is None:
                cur.execute("ALTER TABLE tasks ADD COLUMN is_one_time BOOLEAN NOT NULL DEFAULT false;")
                print(" -> Added 'is_one_time' column to 'tasks' table.")

            # Add date column if it doesn't exist
            cur.execute("""
                SELECT 1 FROM information_schema.columns
                WHERE table_name='tasks' AND column_name='date';
            """)
            if cur.fetchone() is None:
                cur.execute("ALTER TABLE tasks ADD COLUMN date DATE;")
                print(" -> Added 'date' column to 'tasks' table.")

            # Add creation_date column if it doesn't exist
            cur.execute("""
                SELECT 1 FROM information_schema.columns
                WHERE table_name='tasks' AND column_name='creation_date';
            """)
            if cur.fetchone() is None:
                cur.execute("ALTER TABLE tasks ADD COLUMN creation_date DATE;")
                print(" -> Added 'creation_date' column to 'tasks' table.")

            # Check for notes table
            cur.execute("""
                SELECT 1 FROM information_schema.tables
                WHERE table_name='notes';
            """)
            if cur.fetchone() is None:
                cur.execute("""
                    CREATE TABLE notes (
                        id UUID PRIMARY KEY,
                        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
                        title TEXT NOT NULL,
                        content TEXT,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    );
                """)
                print(" -> Created 'notes' table.")

            # Add columns for enhanced note features
            cur.execute("SELECT 1 FROM information_schema.columns WHERE table_name='notes' AND column_name='note_type';")
            if cur.fetchone() is None:
                cur.execute("ALTER TABLE notes ADD COLUMN note_type TEXT NOT NULL DEFAULT 'Standard';")
                print(" -> Added 'note_type' column to 'notes' table.")

            cur.execute("SELECT 1 FROM information_schema.columns WHERE table_name='notes' AND column_name='metadata';")
            if cur.fetchone() is None:
                cur.execute("ALTER TABLE notes ADD COLUMN metadata JSONB;")
                print(" -> Added 'metadata' column to 'notes' table.")

            cur.execute("SELECT 1 FROM information_schema.columns WHERE table_name='notes' AND column_name='tags';")
            if cur.fetchone() is None:
                cur.execute("ALTER TABLE notes ADD COLUMN tags JSONB;")
                print(" -> Added 'tags' column to 'notes' table.")

            conn.commit()
            print("Schema check complete.")

run_migrations()
# --- End Migration ---

# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login_page'

class User(UserMixin):
    def __init__(self, id, username, password_hash):
        self.id = id
        self.username = username
        self.password_hash = password_hash

def get_user_by_username(username):
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE username = %s;", (username,))
            user_data = cur.fetchone()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'])
    return None

def get_user_by_id(user_id):
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE id = %s;", (user_id,))
            user_data = cur.fetchone()
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], password_hash=user_data['password_hash'])
    return None

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

def read_user_tasks():
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, text, \"group\", recurrence, completed_on, habit_tracker, is_one_time, date, creation_date FROM tasks WHERE user_id = %s;", (current_user.id,))
            tasks = cur.fetchall()
            
    for task in tasks:
        task['id'] = str(task['id'])
        task['completedOn'] = task.pop('completed_on')
        task['habitTracker'] = task.pop('habit_tracker')
        task['isOneTime'] = task.pop('is_one_time')
        task['creationDate'] = task.pop('creation_date')
        # Convert date objects to strings, if they exist
        if task['date']:
            task['date'] = task['date'].isoformat()
        if task['creationDate']:
            task['creationDate'] = task['creationDate'].isoformat()

    return tasks

def write_user_tasks(tasks):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM tasks WHERE user_id = %s;", (current_user.id,))
            
            if tasks:
                task_values = [
                    (
                        task['id'],
                        current_user.id,
                        task['text'],
                        task.get('group'),
                        json.dumps(task['recurrence']),
                        json.dumps(task['completedOn']),
                        json.dumps(task.get('habitTracker')),
                        task.get('isOneTime', False),
                        task.get('date'),
                        task.get('creationDate')
                    )
                    for task in tasks
                ]
                
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO tasks (id, user_id, text, "group", recurrence, completed_on, habit_tracker, is_one_time, date, creation_date)
                    VALUES %s
                    """,
                    task_values
                )
        conn.commit()

# --- Authentication Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        user = get_user_by_username(username)
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            # --- MODIFIED: Make the session permanent for the configured lifetime ---
            session.permanent = True
            return jsonify({'success': True, 'message': 'Logged in successfully!', 'redirect': '/~'})
        return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401
    return render_template('login.html')

@app.route('/signup', methods=['GET'])
def signup_page():
    return render_template('signup.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'success': False, 'message': 'Username and password are required.'}), 400

    if get_user_by_username(username):
        return jsonify({'success': False, 'message': 'Username already exists.'}), 409

    new_user_id = str(uuid.uuid4())
    hashed_password = generate_password_hash(password)
    
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO users (id, username, password_hash) VALUES (%s, %s, %s);",
                (new_user_id, username, hashed_password)
            )
            
            today_str = json.dumps(date.today().isoformat())
            default_tasks = [
                {"id": str(uuid.uuid4()), "text": "Click the 'Tasks' title to see your analytics", "group": "App Features", "recurrence": ["Daily"], "isOneTime": False, "date": None, "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}, "creationDate": today_str},
                {"id": str(uuid.uuid4()), "text": "Click the '+' button to add a new task", "group": "App Features", "recurrence": ["Daily"], "isOneTime": False, "date": None, "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}, "creationDate": today_str},
                {"id": str(uuid.uuid4()), "text": "Click this task's text to edit or delete it", "group": "App Features", "recurrence": ["Daily"], "isOneTime": False, "date": None, "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}, "creationDate": today_str},
                {"id": str(uuid.uuid4()), "text": "Click the '0/21' badge to set a habit goal", "group": "App Features", "recurrence": ["Daily"], "isOneTime": False, "date": None, "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}, "creationDate": today_str},
                {"id": str(uuid.uuid4()), "text": "Click a group name to delete the group", "group": "App Features", "recurrence": ["Daily"], "isOneTime": False, "date": None, "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}, "creationDate": today_str},
                {"id": str(uuid.uuid4()), "text": "Use the '‹' and '›' arrows to change the date", "group": "App Features", "recurrence": ["Daily"], "isOneTime": False, "date": None, "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}, "creationDate": today_str},
                {"id": str(uuid.uuid4()), "text": "Changes on this device instantly sync everywhere!", "group": "Welcome", "recurrence": ["Daily"], "isOneTime": False, "date": None, "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}, "creationDate": today_str}
            ]

            if default_tasks:
                task_values = [
                    (
                        task['id'],
                        new_user_id,
                        task['text'],
                        task.get('group'),
                        json.dumps(task['recurrence']),
                        json.dumps(task['completedOn']),
                        json.dumps(task.get('habitTracker')),
                        task.get('isOneTime', False),
                        task.get('date'),
                        task.get('creationDate')
                    )
                    for task in default_tasks
                ]
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO tasks (id, user_id, text, "group", recurrence, completed_on, habit_tracker, is_one_time, date, creation_date)
                    VALUES %s
                    """,
                    task_values
                )
        conn.commit()
    
    new_user = get_user_by_id(new_user_id)
    login_user(new_user)
    # --- MODIFIED: Make the session permanent after registration too ---
    session.permanent = True
    return jsonify({'success': True, 'message': 'Registration successful!', 'redirect': '/~'})

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully.', 'redirect': '/'})

# --- Main Application Routes ---
@app.route('/')
def home():
    if current_user.is_authenticated:
        tasks_data = read_user_tasks()
        return render_template('index.html', username=current_user.username, initial_tasks=tasks_data)
    else:
        return render_template('landing.html')



@app.route('/~')
@login_required
def app_dashboard():
    tasks_data = read_user_tasks()
    return render_template('index.html', username=current_user.username, initial_tasks=tasks_data)

@app.route('/notes')
@login_required
def notes_page():
    return render_template('notes.html', username=current_user.username)

# --- Helper Functions for Smart Notes ---
TMDB_API_KEY = os.environ.get('TMDB_API_KEY', 'f2d7ae9dee829174c475e32fe8f993dc')
TMDB_API_BASE_URL = 'https://api.themoviedb.org/3'

def extract_tags(content):
    """Extracts hashtags from content."""
    return list(set(re.findall(r'#(\w+)', content)))

def fetch_tmdb_data(media_type, tmdb_id):
    """Fetches detailed data for a movie or TV show from the TMDb API."""
    if not all([media_type, tmdb_id, TMDB_API_KEY]):
        return None
    url = f"{TMDB_API_BASE_URL}/{media_type}/{tmdb_id}?api_key={TMDB_API_KEY}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching TMDb data for {media_type} ID {tmdb_id}: {e}")
        return None

def analyze_note_content(content):
    """
    Analyzes note content to determine its type and extract metadata.
    """
    tmdb_movie_pattern = re.compile(r'themoviedb\.org/movie/(\d+)')
    tmdb_tv_pattern = re.compile(r'themoviedb\.org/tv/(\d+)')
    wikipedia_pattern = re.compile(r'wikipedia\.org/wiki/([^/\s\)"\']*)')

    movie_match = tmdb_movie_pattern.search(content)
    if movie_match:
        tmdb_id = movie_match.group(1)
        metadata = fetch_tmdb_data('movie', tmdb_id)
        if metadata:
            return 'Movie', {'tmdb_id': tmdb_id, 'details': metadata}

    tv_match = tmdb_tv_pattern.search(content)
    if tv_match:
        tmdb_id = tv_match.group(1)
        metadata = fetch_tmdb_data('tv', tmdb_id)
        if metadata:
            return 'TV Show', {'tmdb_id': tmdb_id, 'details': metadata}

    wiki_match = wikipedia_pattern.search(content)
    if wiki_match:
        page_title = wiki_match.group(1)
        try:
            page = wikipedia.page(page_title.replace('_', ' '), auto_suggest=False, redirect=True)
            return 'Wikipedia', {'page_title': page.title, 'details': {'title': page.title, 'summary': page.summary, 'url': page.url}}
        except (wikipedia.exceptions.PageError, wikipedia.exceptions.DisambiguationError) as e:
            print(f"Wikipedia error for '{page_title}': {e}")
            return 'Wikipedia', {'page_title': page_title.replace('_',' '), 'details': {'title': page_title.replace('_',' ')}}

    return 'Standard', None


# --- Notes API Routes ---

@app.route('/api/notes', methods=['GET'])
@login_required
def get_notes():
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                "SELECT id, title, content, created_at, updated_at, note_type, metadata, tags FROM notes WHERE user_id = %s ORDER BY updated_at DESC;",
                (current_user.id,)
            )
            notes = cur.fetchall()
    for note in notes:
        note['created_at'] = note['created_at'].isoformat()
        note['updated_at'] = note['updated_at'].isoformat()
    return jsonify(notes)

@app.route('/api/notes', methods=['POST'])
@login_required
def create_note():
    data = request.get_json()
    title = data.get('title')
    content = data.get('content', '')
    if not title:
        return jsonify({'success': False, 'message': 'Title is required.'}), 400

    note_type, metadata = analyze_note_content(content)
    tags = extract_tags(content)
    new_note_id = str(uuid.uuid4())

    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                INSERT INTO notes (id, user_id, title, content, note_type, metadata, tags)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id, title, content, created_at, updated_at, note_type, metadata, tags;
                """,
                (new_note_id, current_user.id, title, content, note_type, json.dumps(metadata) if metadata else None, json.dumps(tags) if tags else '[]')
            )
            new_note = cur.fetchone()
            conn.commit()

    new_note['created_at'] = new_note['created_at'].isoformat()
    new_note['updated_at'] = new_note['updated_at'].isoformat()
    return jsonify({'success': True, 'message': 'Note created successfully.', 'note': new_note}), 201

@app.route('/api/notes/<uuid:note_id>', methods=['PUT'])
@login_required
def update_note(note_id):
    data = request.get_json()
    title = data.get('title')
    content = data.get('content')

    if title is None and content is None:
        return jsonify({'success': False, 'message': 'No fields to update.'}), 400

    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id FROM notes WHERE id = %s AND user_id = %s;", (str(note_id), current_user.id))
            if cur.fetchone() is None:
                return jsonify({'success': False, 'message': 'Note not found or permission denied.'}), 404

            update_fields = []
            params = []
            if title is not None:
                update_fields.append("title = %s")
                params.append(title)

            if content is not None:
                update_fields.append("content = %s")
                params.append(content)
                note_type, metadata = analyze_note_content(content)
                tags = extract_tags(content)
                update_fields.append("note_type = %s")
                params.append(note_type)
                update_fields.append("metadata = %s")
                params.append(json.dumps(metadata) if metadata else None)
                update_fields.append("tags = %s")
                params.append(json.dumps(tags) if tags else '[]')

            update_fields.append("updated_at = CURRENT_TIMESTAMP")

            query = f"UPDATE notes SET {', '.join(update_fields)} WHERE id = %s RETURNING id, title, content, created_at, updated_at, note_type, metadata, tags;"
            params.append(str(note_id))

            cur.execute(query, tuple(params))
            updated_note = cur.fetchone()
            conn.commit()

    updated_note['created_at'] = updated_note['created_at'].isoformat()
    updated_note['updated_at'] = updated_note['updated_at'].isoformat()
    return jsonify({'success': True, 'message': 'Note updated successfully.', 'note': updated_note})

@app.route('/api/notes/<uuid:note_id>', methods=['DELETE'])
@login_required
def delete_note(note_id):
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM notes WHERE id = %s AND user_id = %s;",
                (str(note_id), current_user.id)
            )
            if cur.rowcount == 0:
                return jsonify({'success': False, 'message': 'Note not found or you do not have permission to delete it.'}), 404
            conn.commit()
    return jsonify({'success': True, 'message': 'Note deleted successfully.'})


@app.route('/api/tasks', methods=['GET', 'POST'])
@login_required
def handle_tasks():
    if request.method == 'GET':
        tasks = read_user_tasks()
        return jsonify(tasks)
    
    if request.method == 'POST':
        new_tasks = request.get_json()
        if not isinstance(new_tasks, list):
            return jsonify({'error': 'Invalid data format'}), 400
        
        write_user_tasks(new_tasks)
        socketio.emit('tasks_updated', new_tasks, to=current_user.id)
        return jsonify({'success': True, 'message': 'Tasks saved and synced.'})

# --- WebSocket Event Handlers ---
@socketio.on('connect')
@login_required
def handle_connect():
    if current_user.is_authenticated:
        join_room(current_user.id)
        print(f"Client {request.sid} for user {current_user.username} connected and joined room {current_user.id}")

@socketio.on('disconnect')
def handle_disconnect():
    print(f"Client {request.sid} disconnected")

# --- Local Development Runner ---
if __name__ == '__main__':
    print("Starting development server with WebSocket support...")
    socketio.run(app, debug=True, port=5002, allow_unsafe_werkzeug=True)