import os
import psycopg2
from dotenv import load_dotenv

def main():
    """
    Connects to the PostgreSQL database and sets up the necessary schema
    for the projects feature.
    """
    load_dotenv()
    conn = None
    try:
        db_url = os.environ.get('POSTGRES_URL')
        if not db_url:
            raise Exception("POSTGRES_URL environment variable not set!")

        conn = psycopg2.connect(db_url)
        cur = conn.cursor()

        print("Creating the 'projects' table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS projects (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                title TEXT NOT NULL,
                description TEXT,
                deadline DATE,
                priority TEXT DEFAULT 'medium',
                category TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );
        """)
        print("'projects' table created successfully or already exists.")

        print("Altering the 'tasks' table to add 'project_id'...")
        # Add the column if it doesn't exist
        cur.execute("""
            ALTER TABLE tasks
            ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;
        """)
        print("'tasks' table altered successfully.")

        conn.commit()
        print("Schema changes committed.")

    except Exception as e:
        print(f"An error occurred: {e}")
        if conn:
            conn.rollback()
            print("Changes rolled back.")
    finally:
        if conn:
            cur.close()
            conn.close()
            print("Database connection closed.")

if __name__ == "__main__":
    main()