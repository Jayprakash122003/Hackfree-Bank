import sqlite3

try:
    # Connect to the database
    conn = sqlite3.connect('instance/database.db')
    cursor = conn.cursor()
    
    # Get the schema of the user table
    cursor.execute('PRAGMA table_info(user)')
    columns = cursor.fetchall()
    
    print("User table schema:")
    for column in columns:
        print(column)
    
    # Check if is_administrator column exists
    admin_column = [col for col in columns if col[1] == 'is_administrator']
    if admin_column:
        print("\nis_administrator column exists.")
    else:
        print("\nis_administrator column DOES NOT exist.")
        print("This is likely causing the operational error when logging in.")
    
    conn.close()
except Exception as e:
    print(f"Error checking database: {e}") 