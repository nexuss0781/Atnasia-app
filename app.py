from flask import Flask, render_template, request, jsonify, g, session, redirect, url_for, send_from_directory
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
import click # Added for CLI commands
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here' # IMPORTANT: Change this to a strong, random key in production!

# Database configuration
DATABASE = 'diary.db'

# Upload configuration
UPLOAD_FOLDER = os.path.join(app.root_path, 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row # This makes rows behave like dicts
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        
        # Create entries table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT,
                date TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        
        # Create users table, password_hash can be NULL initially
        # A workaround for directly inserting NULL in CREATE TABLE statement is creating and then altering if needed
        # Or define it as TEXT default NULL
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT DEFAULT NULL
            )
        ''')
        db.commit()

        # Create letters table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS letters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                recipient_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                content TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (recipient_id) REFERENCES users(id)
            )
        ''')
        db.commit()

        # Create messages table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL,
                receiver_id INTEGER NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_id) REFERENCES users(id),
                FOREIGN KEY (receiver_id) REFERENCES users(id)
            )
        ''')
        db.commit()

        # Add default users (Yob, Noon) if they don't exist, with NULL password_hash
        add_default_users(db)

def add_gallery_media_table_migration(db):
    cursor = db.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gallery_media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_type TEXT NOT NULL,
            upload_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    db.commit()
    print("Migration complete: gallery_media table added.")

def add_default_users(db):
    cursor = db.cursor()
    
    # Check if Yob exists, if not, add with NULL password
    cursor.execute("SELECT id FROM users WHERE username = 'Yob'")
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO users (username, password_hash, is_online, last_seen) VALUES (?, ?, ?, ?)", ('Yob', None, 0, None))
        print("Added default user: Yob (password to be set on first login)")
    
    # Check if Noon exists, if not, add with NULL password
    cursor.execute("SELECT id FROM users WHERE username = 'Noon'")
    if cursor.fetchone() is None:
        cursor.execute("INSERT INTO users (username, password_hash, is_online, last_seen) VALUES (?, ?, ?, ?)", ('Noon', None, 0, None))
        print("Added default user: Noon (password to be set on first login)")
    
    db.commit()

def add_chat_columns_to_users_migration(db):
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(users)")
    columns = cursor.fetchall()
    
    is_online_exists = any(col['name'] == 'is_online' for col in columns)
    last_seen_exists = any(col['name'] == 'last_seen' for col in columns)

    if not is_online_exists:
        print("Migrating users table: Adding is_online column.")
        cursor.execute("ALTER TABLE users ADD COLUMN is_online INTEGER DEFAULT 0")
        db.commit()
        print("Migration complete: is_online column added.")

    if not last_seen_exists:
        print("Migrating users table: Adding last_seen column.")
        cursor.execute("ALTER TABLE users ADD COLUMN last_seen DATETIME DEFAULT NULL")
        db.commit()
        print("Migration complete: last_seen column added.")

def migrate_db_schema(db):
    cursor = db.cursor()
    # Check if password_hash column allows NULL
    cursor.execute("PRAGMA table_info(users)")
    columns = cursor.fetchall()
    password_hash_col = next((col for col in columns if col['name'] == 'password_hash'), None)

    if password_hash_col and password_hash_col['notnull'] == 1: # 1 means NOT NULL
        print("Migrating users table: Altering password_hash to allow NULL.")
        cursor.execute("CREATE TABLE users_backup (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT DEFAULT NULL)")
        cursor.execute("INSERT INTO users_backup SELECT id, username, password_hash FROM users")
        cursor.execute("DROP TABLE users")
        cursor.execute("ALTER TABLE users_backup RENAME TO users")
        db.commit()
        print("Migration complete.")

def revert_entries_table_user_id_migration(db):
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(entries)")
    columns = cursor.fetchall()
    user_id_exists = any(col['name'] == 'user_id' for col in columns)

    if user_id_exists:
        print("Reverting entries table migration: Removing user_id column.")
        cursor.execute('''
            CREATE TABLE new_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT,
                date TEXT NOT NULL
            )
        ''')
        cursor.execute("INSERT INTO new_entries (id, title, content, date) SELECT id, title, content, date FROM entries")
        cursor.execute("DROP TABLE entries")
        cursor.execute("ALTER TABLE new_entries RENAME TO entries")
        db.commit()
        print("Entries table migration reverted: user_id column removed.")

def add_user_id_to_entries_migration(db):
    cursor = db.cursor()
    cursor.execute("PRAGMA table_info(entries)")
    columns = cursor.fetchall()
    user_id_exists = any(col['name'] == 'user_id' for col in columns)

    if not user_id_exists:
        print("Migrating entries table: Adding user_id column.")
        
        # Get Yob's user_id to assign to existing entries
        cursor.execute("SELECT id FROM users WHERE username = 'Yob'")
        yob_id_row = cursor.fetchone()
        yob_id = yob_id_row['id'] if yob_id_row else None

        if yob_id is None:
            print("Error: 'Yob' user not found. Cannot assign existing entries to a user.")
            raise ValueError("Yob user not found, cannot migrate entries.")

        # Recreate table with NOT NULL constraint and foreign key
        cursor.execute('''
            CREATE TABLE new_entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT,
                date TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        ''')
        # Copy data, assigning existing entries to Yob
        cursor.execute("INSERT INTO new_entries (id, title, content, date, user_id) SELECT id, title, content, date, ? FROM entries", (yob_id,))
        cursor.execute("DROP TABLE entries")
        cursor.execute("ALTER TABLE new_entries RENAME TO entries")
        db.commit()
        print("Entries table migration complete: user_id column added and set to NOT NULL.")

# Initialize the database when the app starts
with app.app_context():
    init_db()
    migrate_db_schema(get_db()) # Call migration after init_db
    add_user_id_to_entries_migration(get_db()) # Add user_id to entries table
    add_chat_columns_to_users_migration(get_db()) # Add chat related columns to users table
    add_gallery_media_table_migration(get_db()) # Add gallery_media table migration

# --- Authentication Check for Protected Routes ---
@app.before_request
def check_user_logged_in():
    # List of routes that do NOT require authentication
    if request.endpoint in ['index', 'index_html', 'login_api']:
        return
    
    # All other routes require authentication
    if 'username' not in session:
        # For API requests, return a 401 Unauthorized
        if request.path.startswith('/api/'):
            return jsonify({'error': 'Unauthorized'}), 401
        # For HTML pages, redirect to the index page (login page)
        return redirect(url_for('index'))

# --- HTML Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/index.html')
def index_html():
    return render_template('index.html')

@app.route('/about_us.html')
def about_us():
    return render_template('about_us.html')

@app.route('/chat.html')
def chat():
    return render_template('Chat.html')

@app.route('/home.html')
def home():
    return render_template('home.html', username=session.get('username'))

@app.route('/my_letter.html')
def my_letter():
    return render_template('my_letter.html')

@app.route('/noon_copy.html')
def noon_copy():
    return render_template('noon copy.html')

@app.route('/noon.html')
def noon():
    return render_template('noon.html')

@app.route('/universe.html')
def universe():
    return render_template('universe.html')

@app.route('/your_love.html')
def your_love():
    return render_template('your_love.html')

# --- API Routes for Diary Entries ---
@app.route('/api/diary', methods=['GET'])
def get_diary_entries():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT 
            e.id, e.title, e.content, e.date, u.username as owner_username
        FROM 
            entries e
        JOIN 
            users u ON e.user_id = u.id
        ORDER BY 
            e.date DESC
    """)
    entries = cursor.fetchall()
    entries_list = []
    for entry in entries:
        entries_list.append(dict(entry))
    return jsonify(entries_list)

@app.route('/api/diary', methods=['POST'])
def add_diary_entry():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    data = request.get_json()
    title = data.get('title', 'Untitled Entry')
    content = data.get('content', '')
    date = data.get('date', '')
    if not date:
        from datetime import datetime
        date = datetime.now().isoformat()

    db = get_db()
    cursor = db.cursor()
    user_id = session['user_id']
    cursor.execute("INSERT INTO entries (title, content, date, user_id) VALUES (?, ?, ?, ?)", (title, content, date, user_id))
    db.commit()
    new_entry_id = cursor.lastrowid
    return jsonify({'id': new_entry_id, 'title': title, 'content': content, 'date': date, 'user_id': user_id}), 201

@app.route('/api/diary/<int:entry_id>', methods=['PUT'])
def update_diary_entry(entry_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    data = request.get_json()
    title = data.get('title')
    content = data.get('content')
    
    if not title and not content:
        return jsonify({'error': 'No data provided for update'}), 400

    db = get_db()
    cursor = db.cursor()
    
    update_fields = []
    update_values = []
    if title is not None:
        update_fields.append("title = ?")
        update_values.append(title)
    if content is not None:
        update_fields.append("content = ?")
        update_values.append(content)
    
    update_fields.append("date = ?") # Update date on modification
    from datetime import datetime
    update_values.append(datetime.now().isoformat())

    user_id = session['user_id']
    update_query = f"UPDATE entries SET {', '.join(update_fields)} WHERE id = ? AND user_id = ?"
    update_values.append(entry_id)
    update_values.append(user_id)

    cursor.execute(update_query, tuple(update_values))
    db.commit()

    if cursor.rowcount == 0:
        return jsonify({'error': 'Entry not found or you do not have permission to edit this entry'}), 403 # Changed to 403 Forbidden
    return jsonify({'message': 'Entry updated successfully'}), 200

# Removed DELETE API routes as per user request to avoid delete functionality.

# --- Authentication API Routes ---
@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    db = get_db()
    cursor = db.cursor()
    
    # Try to find the user
    cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()

    if user:
        # User exists
        if user['password_hash'] is None:
            # First login for this user, set their password
            hashed_password = generate_password_hash(password)
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hashed_password, user['id']))
            db.commit()
            
            session['username'] = user['username']
            session['user_id'] = user['id']
            return jsonify({'message': 'Password set and login successful', 'username': user['username']}), 200
        elif check_password_hash(user['password_hash'], password):
            # Existing user, password matches
            session['username'] = user['username']
            session['user_id'] = user['id']
            return jsonify({'message': 'Login successful', 'username': user['username']}), 200
        else:
            # Existing user, password mismatch
            return jsonify({'error': 'Invalid username or password'}), 401
    else:
        # This case should ideally not be hit for Yob/Noon if add_default_users works correctly
        # if you want to allow dynamic user creation, this is where you'd add it. (currently returns error)
        return jsonify({'error': 'Invalid username or password'}), 401

@app.route('/api/logout', methods=['POST'])
def logout_api():
    session.pop('username', None)
    session.pop('user_id', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/api/current_user', methods=['GET'])
def get_current_user():
    username = session.get('username')
    return jsonify({'username': username})

@app.route('/api/partner_username', methods=['GET'])
def get_partner_username():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT username FROM users WHERE id != ?", (user_id,))
    partner_row = cursor.fetchone()
    
    if partner_row:
        return jsonify({'partner_username': partner_row['username']}), 200
    else:
        return jsonify({'error': 'Partner not found.'}), 404

@app.route('/api/users/other_id', methods=['GET'])
def get_other_user_id():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    current_user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("SELECT id FROM users WHERE id != ?", (current_user_id,))
    other_user_row = cursor.fetchone()
    
    if other_user_row:
        return jsonify({'other_user_id': other_user_row['id']}), 200
    else:
        return jsonify({'error': 'Other user not found.'}), 404

@app.route('/api/current_user_id', methods=['GET'])
def get_current_user_id():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401
    return jsonify({'current_user_id': session['user_id']}), 200

@app.route('/api/letters', methods=['POST'])
def send_letter():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    data = request.get_json()
    title = data.get('title', 'Untitled Letter')
    content = data.get('content', '')
    
    sender_id = session['user_id']
    
    db = get_db()
    cursor = db.cursor()

    # Determine recipient_id (the other user)
    cursor.execute("SELECT id FROM users WHERE id != ?", (sender_id,))
    recipient_row = cursor.fetchone()
    if not recipient_row:
        return jsonify({'error': 'Recipient user not found.'}), 500
    recipient_id = recipient_row['id']

    cursor.execute(
        "INSERT INTO letters (sender_id, recipient_id, title, content) VALUES (?, ?, ?, ?)",
        (sender_id, recipient_id, title, content)
    )
    db.commit()
    new_letter_id = cursor.lastrowid
    return jsonify({'message': 'Letter sent successfully', 'id': new_letter_id}), 201

@app.route('/api/letters/sent', methods=['GET'])
def get_sent_letters():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT 
            l.id, l.title, l.content, l.timestamp, u.username as recipient_username
        FROM 
            letters l
        JOIN 
            users u ON l.recipient_id = u.id
        WHERE 
            l.sender_id = ?
        ORDER BY 
            l.timestamp DESC
    """, (user_id,))
    letters = cursor.fetchall()
    letters_list = []
    for letter in letters:
        letters_list.append(dict(letter))
    return jsonify(letters_list)

@app.route('/api/letters/received', methods=['GET'])
def get_received_letters():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        SELECT 
            l.id, l.title, l.content, l.timestamp, u.username as sender_username
        FROM 
            letters l
        JOIN 
            users u ON l.sender_id = u.id
        WHERE 
            l.recipient_id = ?
        ORDER BY 
            l.timestamp DESC
    """, (user_id,))
    letters = cursor.fetchall()
    letters_list = []
    for letter in letters:
        letters_list.append(dict(letter))
    return jsonify(letters_list)

# --- API Routes for Chat ---
@app.route('/api/chat/message', methods=['POST'])
def send_chat_message():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    data = request.get_json()
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'Message content cannot be empty.'}), 400

    sender_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # Determine receiver_id (the other user)
    cursor.execute("SELECT id FROM users WHERE id != ?", (sender_id,))
    receiver_row = cursor.fetchone()
    if not receiver_row:
        return jsonify({'error': 'Receiver user not found.'}), 500
    receiver_id = receiver_row['id']

    cursor.execute(
        "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
        (sender_id, receiver_id, content)
    )
    db.commit()
    new_message_id = cursor.lastrowid
    
    # Update sender's last_seen
    from datetime import datetime
    cursor.execute("UPDATE users SET last_seen = ? WHERE id = ?", (datetime.now().isoformat(), sender_id))
    db.commit()

    return jsonify({'message': 'Message sent successfully', 'id': new_message_id, 'timestamp': datetime.now().isoformat()}), 201

@app.route('/api/chat/messages', methods=['GET'])
def get_chat_messages():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    current_user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # Get the other user's ID
    cursor.execute("SELECT id FROM users WHERE id != ?", (current_user_id,))
    other_user_row = cursor.fetchone()
    if not other_user_row:
        return jsonify({'error': 'Other user not found.'}), 500
    other_user_id = other_user_row['id']

    # Fetch messages between current_user and other_user
    cursor.execute("""
        SELECT 
            m.id, m.content, m.timestamp, 
            s.username as sender_username, 
            r.username as receiver_username,
            m.sender_id
        FROM 
            messages m
        JOIN 
            users s ON m.sender_id = s.id
        JOIN 
            users r ON m.receiver_id = r.id
        WHERE 
            (m.sender_id = ? AND m.receiver_id = ?) OR 
            (m.sender_id = ? AND m.receiver_id = ?)
        ORDER BY 
            m.timestamp ASC
    """, (current_user_id, other_user_id, other_user_id, current_user_id))
    
    messages = cursor.fetchall()
    messages_list = []
    for msg in messages:
        messages_list.append(dict(msg))
    return jsonify(messages_list)

@app.route('/api/chat/message/<int:message_id>', methods=['PUT'])
def update_chat_message(message_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    data = request.get_json()
    new_content = data.get('content', '').strip()
    if not new_content:
        return jsonify({'error': 'Message content cannot be empty.'}), 400

    current_user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # Verify message ownership
    cursor.execute("SELECT sender_id FROM messages WHERE id = ?", (message_id,))
    message = cursor.fetchone()

    if not message:
        return jsonify({'error': 'Message not found.'}), 404
    if message['sender_id'] != current_user_id:
        return jsonify({'error': 'Forbidden: You can only edit your own messages.'}), 403

    from datetime import datetime
    cursor.execute(
        "UPDATE messages SET content = ?, timestamp = ? WHERE id = ?",
        (new_content, datetime.now().isoformat(), message_id)
    )
    db.commit()
    return jsonify({'message': 'Message updated successfully', 'id': message_id, 'new_timestamp': datetime.now().isoformat()}), 200

@app.route('/api/chat/message/<int:message_id>', methods=['DELETE'])
def delete_chat_message(message_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    current_user_id = session['user_id']
    db = get_db()
    cursor = db.cursor()

    # Verify message ownership
    cursor.execute("SELECT sender_id FROM messages WHERE id = ?", (message_id,))
    message = cursor.fetchone()

    if not message:
        return jsonify({'error': 'Message not found.'}), 404
    if message['sender_id'] != current_user_id:
        return jsonify({'error': 'Forbidden: You can only delete your own messages.'}), 403

    cursor.execute("DELETE FROM messages WHERE id = ?", (message_id,))
    db.commit()
    return jsonify({'message': 'Message deleted successfully', 'id': message_id}), 200

# --- API Routes for Gallery Media ---
@app.route('/api/upload_media', methods=['POST'])
def upload_media():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file:
        filename = secure_filename(file.filename)
        # Create user-specific folder
        user_upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], str(session['user_id']))
        os.makedirs(user_upload_folder, exist_ok=True)
        
        file_path_on_disk = os.path.join(user_upload_folder, filename)
        file.save(file_path_on_disk)

        # Define relative_file_path before its usage
        relative_file_path = os.path.join('uploads', str(session['user_id']), filename)

        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO gallery_media (user_id, filename, file_path, file_type) VALUES (?, ?, ?, ?)",
            (session['user_id'], filename, relative_file_path, file.content_type)
        )
        db.commit()
        media_id = cursor.lastrowid

        return jsonify({
            'message': 'File uploaded successfully',
            'id': media_id,
            'filename': filename,
            'file_path': relative_file_path, # This is the URL path for the frontend
            'file_type': file.content_type
        }), 201
    
    return jsonify({'error': 'File upload failed'}), 500

@app.route('/api/get_media', methods=['GET'])
def get_media():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute(
        "SELECT id, filename, file_path, file_type, upload_timestamp FROM gallery_media WHERE user_id = ? ORDER BY upload_timestamp DESC",
        (session['user_id'],)
    )
    media_items = cursor.fetchall()
    media_list = []
    for item in media_items:
        media_dict = dict(item)
        # Adjust file_path to be a URL accessible from the frontend
        media_dict['file_path'] = url_for('uploaded_file', filename=os.path.join(str(session['user_id']), media_dict['filename']))
        media_list.append(media_dict)
    return jsonify(media_list)

@app.route('/api/delete_media/<int:media_id>', methods=['DELETE'])
def delete_media(media_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    db = get_db()
    cursor = db.cursor()

    # Verify ownership and get file path
    cursor.execute("SELECT file_path FROM gallery_media WHERE id = ? AND user_id = ?", (media_id, session['user_id']))
    media_item = cursor.fetchone()

    if not media_item:
        return jsonify({'error': 'Media item not found or you do not have permission to delete this item.'}), 403

    stored_file_path_in_db = media_item['file_path']
    
    # Determine the relative path for the security check
    # If the stored path is absolute, extract the relative part
    if os.path.isabs(stored_file_path_in_db):
        # Assuming absolute path looks like /data/.../atnesia-app/uploads/user_id/filename
        # We need to get 'uploads/user_id/filename' part
        relative_path_for_check = os.path.relpath(stored_file_path_in_db, app.root_path)
    else:
        # It's already a relative path (e.g., 'uploads/user_id/filename')
        relative_path_for_check = stored_file_path_in_db

    # Ensure the file path is within the UPLOAD_FOLDER to prevent directory traversal attacks
    expected_prefix = os.path.join('uploads', str(session['user_id']))
    if not relative_path_for_check.startswith(expected_prefix):
        return jsonify({'error': 'Invalid file path.'}), 400

    # Construct the absolute path to delete the file
    # Use the stored_file_path_in_db directly to construct the absolute path
    # This handles both old absolute paths and new relative paths correctly
    if os.path.isabs(stored_file_path_in_db):
        absolute_file_path = stored_file_path_in_db
    else:
        absolute_file_path = os.path.join(app.root_path, stored_file_path_in_db)
    
    if os.path.exists(absolute_file_path):
        os.remove(absolute_file_path)
    else:
        print(f"Warning: File not found on disk: {absolute_file_path}")

    cursor.execute("DELETE FROM gallery_media WHERE id = ?", (media_id,))
    db.commit()

    return jsonify({'message': 'Media item deleted successfully', 'id': media_id}), 200

# Route to serve uploaded files
@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/api/chat/status', methods=['POST'])
def update_user_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    user_id = session['user_id']
    data = request.get_json()
    is_online = data.get('is_online', None)
    
    db = get_db()
    cursor = db.cursor()
    from datetime import datetime

    if is_online is not None:
        cursor.execute("UPDATE users SET is_online = ?, last_seen = ? WHERE id = ?", (1 if is_online else 0, datetime.now().isoformat(), user_id))
    else: # Just update last_seen if no online status provided
        cursor.execute("UPDATE users SET last_seen = ? WHERE id = ?", (datetime.now().isoformat(), user_id))
    
    db.commit()
    return jsonify({'message': 'Status updated successfully'}), 200

@app.route('/api/chat/status/<int:user_id>', methods=['GET'])
def get_other_user_status(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT username, is_online, last_seen FROM users WHERE id = ?", (user_id,))
    user_status = cursor.fetchone()

    if user_status:
        return jsonify(dict(user_status)), 200
    return jsonify({'error': 'User not found'}), 404

# Placeholder for typing status (will be handled client-side with polling for now)
# For a true real-time typing indicator, WebSockets would be ideal.
# For this implementation, we'll simulate it with client-side logic and polling.
_typing_status = {} # In-memory store for typing status

@app.route('/api/chat/typing', methods=['POST'])
def update_typing_status():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401
    
    user_id = session['user_id']
    data = request.get_json()
    is_typing = data.get('is_typing', False)
    
    _typing_status[user_id] = is_typing
    return jsonify({'message': 'Typing status updated'}), 200

@app.route('/api/chat/typing/<int:user_id>', methods=['GET'])
def get_typing_status(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized: User not logged in.'}), 401
    
    is_typing = _typing_status.get(user_id, False)
    return jsonify({'is_typing': is_typing}), 200

@app.cli.command('clear-passwords')
def clear_user_passwords_cli():
    """Clears the password hashes for Yob and Noon in the database."""
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        cursor.execute("UPDATE users SET password_hash = NULL WHERE username IN ('Yob', 'Noon')")
        db.commit()
        print("Password hashes for Yob and Noon have been cleared.")

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
