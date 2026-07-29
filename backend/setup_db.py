import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Admin connection (to postgres database)
ADMIN_DB_CONFIG = {
    "host": os.getenv("POSTGRES_HOST", "localhost"),
    "port": os.getenv("POSTGRES_PORT", "5432"),
    "dbname": "postgres",  # Always exists
    "user": "postgres",
    "password": os.getenv("POSTGRES_PASSWORD_ADMIN")
}

# Platform database config
PLATFORM_DB_NAME = os.getenv("POSTGRES_DB", "cyber_range")
PLATFORM_USER = os.getenv("POSTGRES_USER", "cyber_range_user")
PLATFORM_PASSWORD = os.getenv("POSTGRES_PASSWORD")

def setup_database():
    """Create the database and user if they don't exist."""
    
    print("🔧 Setting up PostgreSQL database...")
    
    try:
        # Connect as admin (postgres user)
        conn = psycopg2.connect(**ADMIN_DB_CONFIG)
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (PLATFORM_USER,))
        user_exists = cursor.fetchone()
        
        if not user_exists:
            print(f"👤 Creating user: {PLATFORM_USER}")
            cursor.execute(f"CREATE USER {PLATFORM_USER} WITH PASSWORD %s", (PLATFORM_PASSWORD,))
            print(f"✅ User {PLATFORM_USER} created")
        else:
            print(f"✅ User {PLATFORM_USER} already exists")
        
        # Check if database exists
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (PLATFORM_DB_NAME,))
        db_exists = cursor.fetchone()
        
        if not db_exists:
            print(f"📁 Creating database: {PLATFORM_DB_NAME}")
            cursor.execute(f"CREATE DATABASE {PLATFORM_DB_NAME}")
            print(f"✅ Database {PLATFORM_DB_NAME} created")
            
            # Grant privileges on the database
            cursor.execute(f"GRANT ALL PRIVILEGES ON DATABASE {PLATFORM_DB_NAME} TO {PLATFORM_USER}")
            print(f"✅ Privileges granted to {PLATFORM_USER}")
        else:
            print(f"✅ Database {PLATFORM_DB_NAME} already exists")
        
        conn.close()
        
        # ============================================================
        # NEW: Grant schema permissions (PostgreSQL 15+ fix)
        # ============================================================
        print("\n🔧 Granting schema permissions...")
        
        # Connect to the platform database directly
        DB_CONN_CONFIG = {
            "host": os.getenv("POSTGRES_HOST", "localhost"),
            "port": os.getenv("POSTGRES_PORT", "5432"),
            "dbname": PLATFORM_DB_NAME,
            "user": "postgres",
            "password": os.getenv("POSTGRES_PASSWORD_ADMIN")
        }
        
        db_conn = psycopg2.connect(**DB_CONN_CONFIG)
        db_conn.autocommit = True
        db_cursor = db_conn.cursor()
        
        # Grant schema permissions
        db_cursor.execute(f"GRANT ALL ON SCHEMA public TO {PLATFORM_USER}")
        db_cursor.execute(f"GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {PLATFORM_USER}")
        db_cursor.execute(f"GRANT USAGE, CREATE ON SCHEMA public TO {PLATFORM_USER}")
        
        db_conn.close()
        print("✅ Schema permissions granted")
        
        print("\n✅ Database setup complete!")
        return True
        
    except Exception as e:
        print(f"❌ Setup failed: {e}")
        print("\nMake sure PostgreSQL is running and you have the correct admin password in .env")
        return False

if __name__ == "__main__":
    setup_database()