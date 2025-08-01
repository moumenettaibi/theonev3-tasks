# migrate_data.py
import os
import json
import psycopg2

# --- CONFIGURATION ---
# Make sure these file paths are correct relative to where you run the script
USERS_FILE = 'users.json'
# The user ID is the name of the tasks file
USER_ID = 'e189dd8f-b063-4cc7-a44e-674eaae020fa'
TASKS_FILE = f'{USER_ID}.json' 
# --- END CONFIGURATION ---


def get_db_connection():
    """Establishes a connection to the database from the environment variable."""
    db_url = os.environ.get('POSTGRES_URL')
    if not db_url:
        raise Exception("POSTGRES_URL environment variable not set!")
    conn = psycopg2.connect(db_url)
    return conn

def migrate():
    """Reads data from JSON files and inserts it into the database."""
    # Read data from files
    try:
        with open(USERS_FILE, 'r') as f:
            users_data = json.load(f)
        with open(TASKS_FILE, 'r') as f:
            tasks_data = json.load(f)
    except FileNotFoundError as e:
        print(f"Error: Could not find a required file: {e.filename}")
        return

    user_info = users_data.get(USER_ID)
    if not user_info:
        print(f"Error: Could not find user with ID {USER_ID} in {USERS_FILE}")
        return

    conn = get_db_connection()
    cur = conn.cursor()
    
    print(f"Migrating user: {user_info['username']}...")
    try:
        # Check if user already exists
        cur.execute("SELECT id FROM users WHERE id = %s;", (USER_ID,))
        if cur.fetchone():
            print("User already exists in the database. Skipping user insertion.")
        else:
            # Insert the user
            cur.execute(
                "INSERT INTO users (id, username, password_hash) VALUES (%s, %s, %s);",
                (USER_ID, user_info['username'], user_info['password_hash'])
            )
            print("User inserted successfully.")

        # Delete any existing tasks for this user to avoid duplicates
        cur.execute("DELETE FROM tasks WHERE user_id = %s;", (USER_ID,))
        print(f"Cleared any old tasks for user {USER_ID}.")

        # Insert the tasks
        print(f"Migrating {len(tasks_data)} tasks...")
        for task in tasks_data:
            cur.execute(
                """
                INSERT INTO tasks (id, user_id, text, "group", recurrence, completed_on, habit_tracker)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    task['id'],
                    USER_ID,
                    task['text'],
                    task.get('group'),
                    json.dumps(task['recurrence']),
                    json.dumps(task['completedOn']),
                    json.dumps(task['habitTracker'])
                )
            )
        
        print("Tasks inserted successfully.")
        
        # Commit all changes to the database
        conn.commit()
        print("\nMigration complete! All data has been saved to the database.")

    except Exception as e:
        print(f"\nAn error occurred: {e}")
        print("Rolling back changes.")
        conn.rollback()
    finally:
        cur.close()
        conn.close()

if __name__ == '__main__':
    migrate()