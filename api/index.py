# api/index.py

import os
import json
import uuid
import atexit
import psycopg2
import psycopg2.extras
import google.generativeai as genai
from psycopg2.pool import SimpleConnectionPool
from contextlib import contextmanager

from flask import Flask, render_template, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from apscheduler.schedulers.background import BackgroundScheduler

from dotenv import load_dotenv
load_dotenv()

# --- App & SocketIO Setup ---
app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'a-strong-dev-secret-key')
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

# --- Gemini AI Configuration ---
try:
    GEMINI_API_KEY = os.environ['GEMINI_API_KEY']
    genai.configure(api_key=GEMINI_API_KEY)
    ai_model = genai.GenerativeModel('gemini-2.5-flash')
except KeyError:
    raise RuntimeError("GEMINI_API_KEY not found in environment variables. Please add it to your .env file.")

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
            cur.execute("SELECT id, text, \"group\", recurrence, completed_on, habit_tracker FROM tasks WHERE user_id = %s;", (current_user.id,))
            tasks = cur.fetchall()

    for task in tasks:
        task['id'] = str(task['id'])
        task['completedOn'] = task.pop('completed_on')
        task['habitTracker'] = task.pop('habit_tracker')
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
                        json.dumps(task['habitTracker'])
                    )
                    for task in tasks
                ]

                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO tasks (id, user_id, text, "group", recurrence, completed_on, habit_tracker)
                    VALUES %s
                    """,
                    task_values
                )
        conn.commit()

# --- AI Progressive Overload Feature ---

def get_all_tasks_for_ai():
    """Fetches all tasks from the database for the AI to process."""
    with get_db_connection() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT id, text FROM tasks;")
            tasks = cur.fetchall()
    return tasks

def update_task_text_in_db(task_id, new_text):
    """Updates the text of a specific task in the database."""
    with get_db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE tasks SET text = %s WHERE id = %s;", (new_text, task_id))
        conn.commit()

def run_progressive_overload():
    """
    The core AI function. It gets all tasks, asks the AI to make them
    incrementally harder, and updates them in the database.
    This function is executed by the scheduler.
    """
    with app.app_context():
        print("AI Cron Job: Starting progressive overload cycle...")
        all_tasks = get_all_tasks_for_ai()

        if not all_tasks:
            print("AI Cron Job: No tasks found to process.")
            return

        for task in all_tasks:
            try:
                original_text = task['text']
                prompt = f"""
                Analyze the following task and make it slightly more difficult for the next week. This is for a progressive overload system.

                Guidelines:
                - If the task has a number (e.g., "Read 10 pages", "Do 30 push-ups"), increase the number by a small, reasonable amount (e.g., 5-15%).
                - If the task has a time (e.g., "Sleep at 23:00", "Meditate for 15 minutes"), adjust the time to be slightly more challenging (e.g., make bedtime 15-30 minutes earlier, or meditation slightly longer).
                - If the task is a simple habit (e.g., "Drink water in the morning"), do NOT change it.
                - The new task name should be concise and similar in style to the original. Do NOT add commentary. Just provide the updated task text.
                - If no change is logical, return the original text exactly as it is.

                Original task: "{original_text}"
                New task:
                """

                response = ai_model.generate_content(prompt)
                new_text = response.text.strip()

                # Basic validation to ensure AI doesn't go wild
                if 0 < len(new_text) < 150 and new_text != original_text:
                    print(f"AI Cron Job: Updating task '{original_text}' to '{new_text}'")
                    update_task_text_in_db(task['id'], new_text)
                else:
                    print(f"AI Cron Job: No change for task '{original_text}'")

            except Exception as e:
                print(f"AI Cron Job: Error processing task ID {task['id']}: {e}")

        print("AI Cron Job: Progressive overload cycle finished.")


# --- Scheduler Setup ---
scheduler = BackgroundScheduler(daemon=True)
# Schedule the job to run every Monday at 3:00 AM
scheduler.add_job(run_progressive_overload, 'cron', day_of_week='mon', hour=3, minute=0)
scheduler.start()

# --- Graceful Shutdown ---
@atexit.register
def shutdown_scheduler():
    if scheduler.running:
        scheduler.shutdown()
        print("Scheduler shut down successfully.")


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
            return jsonify({'success': True, 'message': 'Logged in successfully!'})
        return jsonify({'success': False, 'message': 'Invalid username or password.'}), 401
    return render_template('login.html')

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

            default_tasks = [
                {"id": str(uuid.uuid4()), "text": "Click 'Tasks' title for analytics", "group": "App Features", "recurrence": ["Daily"], "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}},
                {"id": str(uuid.uuid4()), "text": "Changes on this device will instantly sync everywhere!", "group": "Welcome", "recurrence": ["Daily"], "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}},
                {"id": str(uuid.uuid4()), "text": "AI will make some tasks harder each Monday!", "group": "App Features", "recurrence": ["Daily"], "completedOn": {}, "habitTracker": {"goal": 21, "completedDates": []}}
            ]

            if default_tasks:
                task_values = [
                    (
                        task['id'], new_user_id, task['text'], task.get('group'),
                        json.dumps(task['recurrence']), json.dumps(task['completedOn']), json.dumps(task['habitTracker'])
                    )
                    for task in default_tasks
                ]
                psycopg2.extras.execute_values(
                    cur,
                    """
                    INSERT INTO tasks (id, user_id, text, "group", recurrence, completed_on, habit_tracker)
                    VALUES %s
                    """,
                    task_values
                )
        conn.commit()

    new_user = get_user_by_id(new_user_id)
    login_user(new_user)
    return jsonify({'success': True, 'message': 'Registration successful!'})

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'success': True, 'message': 'Logged out successfully.'})

# --- Main Application Routes ---
@app.route('/')
@login_required
def home():
    tasks_data = read_user_tasks()
    return render_template('index.html', username=current_user.username, initial_tasks=tasks_data)

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
    # The allow_unsafe_werkzeug flag is for the reloader. In production, use a proper WSGI server like Gunicorn.
    socketio.run(app, debug=True, port=5001, allow_unsafe_werkzeug=True)