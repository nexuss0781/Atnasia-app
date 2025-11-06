# Atnesiya App

## Project Title and Description
**Atnesiya** is a personal web application designed for couples to share memories, thoughts, and communicate in a private and intimate space. It features a digital diary, a letter exchange system, a real-time chat, and a media gallery to store cherished moments. The application aims to provide a secure and beautiful platform for partners to connect and preserve their shared journey.

## Features
*   **User Authentication:** Secure login system for two predefined users (Yob and Noon).
*   **Digital Diary:**
    *   Create, view, and update personal diary entries.
    *   Entries are associated with the logged-in user.
*   **Letter Exchange:**
    *   Send private letters to your partner.
    *   View sent and received letters.
*   **Real-time Chat:**
    *   Engage in real-time messaging with your partner.
    *   Typing indicators and online/offline status.
    *   Edit, delete, and copy message options via long-press/context menu.
*   **Noon Gallery:**
    *   Upload and manage photos, videos, and other files.
    *   Persistent storage of media files in a dedicated server folder.
    *   View media in a lightbox.
    *   Delete uploaded media.
*   **Animated Backgrounds:** Visually appealing animated particles and hearts for an enhanced user experience.

## Technologies Used
*   **Backend:** Flask (Python)
*   **Database:** SQLite3
*   **Frontend:** HTML, CSS, JavaScript
*   **Styling:** Custom CSS, Font Awesome for icons
*   **Security:** `werkzeug.security` for password hashing, `secure_filename` for file uploads.

## Setup and Installation

### Prerequisites
*   Python 3.8+
*   `pip` (Python package installer)

### Cloning the Repository
```bash
git clone https://github.com/your-username/atnesia-app.git
cd atnesia-app
```
*(Note: Replace `https://github.com/your-username/atnesia-app.git` with the actual repository URL if different.)*

### Setting up the Virtual Environment
It's highly recommended to use a virtual environment to manage dependencies.
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### Installing Dependencies
Install the required Python packages using `pip`:
```bash
pip install -r requirements.txt
```
*(If `requirements.txt` is missing, you can create it by running `pip freeze > requirements.txt` after manually installing Flask, SQLite3, Werkzeug, etc., or install them directly: `pip install Flask Flask-SQLAlchemy Flask-Login Flask-Bcrypt email_validator Werkzeug`)*

### Initializing the Database
The application uses SQLite and will create `diary.db` and necessary tables (users, entries, letters, messages, gallery_media) on startup if they don't exist. It also adds default users 'Yob' and 'Noon'.
```bash
python app.py
# The database will be initialized automatically when app.py runs for the first time.
# You might see messages like "Migration complete: gallery_media table added."
```
**Note:** The default users 'Yob' and 'Noon' will have `NULL` passwords initially. The first time you log in with either username, you will set their password.

### Running the Application
To start the Flask development server:
```bash
python app.py
```
The application will typically run on `http://127.0.0.1:5000/`. Open this URL in your web browser.

## Usage

### Login/User Management
*   Navigate to the application URL (`http://127.0.0.1:5000/`).
*   Log in with either `Yob` or `Noon`. The first time you log in, you will be prompted to set a password for that user.
*   You can switch between users by logging out and logging back in.

### Digital Diary
*   Access the diary section from the home page.
*   Create new entries, view existing ones, and update them.

### Letters
*   Send private letters to your partner.
*   View letters you have sent and received.

### Chat
*   Engage in real-time chat with your partner.
*   **Message Options:** Long-press (or right-click on desktop) on a message bubble to reveal options to Edit, Delete, or Copy the message.
    *   **Edit:** Only your own messages can be edited.
    *   **Delete:** Only your own messages can be deleted.
    *   **Copy:** Any message can be copied to your clipboard.

### Noon Gallery (Media Uploads)
*   Access the gallery from the home page.
*   **Upload:** Click the "Upload box" to select photos, videos, or other files. Files are stored persistently on the server in a user-specific folder.
*   **View:** Click on any media item to open it in a lightbox for a larger view.
*   **Delete:** Each media item has a small 'x' button to delete it. Only media you uploaded can be deleted.

## Project Structure
```
atnesia-app/
├── app.py                  # Main Flask application file
├── diary.db                # SQLite database file (generated on first run)
├── requirements.txt        # Python dependencies
├── __pycache__/            # Python cache files
├── .vscode/                # VS Code configuration
├── static/                 # Static files (CSS, JS, images - if any)
├── templates/              # HTML template files
│   ├── about_us.html
│   ├── Chat.html
│   ├── home.html
│   ├── index.html
│   ├── my_letter.html
│   ├── noon copy.html
│   ├── noon.html           # Gallery page
│   ├── universe.html
│   └── your_love.html
└── venv/                   # Python virtual environment
└── uploads/                # Directory for uploaded media files (created on first upload)
    └── <user_id>/          # Subdirectories for each user's uploads
        └── <filename>      # Uploaded files
```

## Future Enhancements (Optional)
*   **User Registration:** Allow new users to register instead of relying on predefined users.
*   **Profile Management:** Add user profile pages with customizable avatars.
*   **Notifications:** Implement real-time notifications for new messages, letters, or uploads.
*   **Improved Media Previews:** Generate proper video thumbnails on the server-side.
*   **Search Functionality:** Add search to diary entries, letters, and gallery.
*   **Theming:** Allow users to customize the app's theme.
*   **WebSockets for Chat:** Upgrade chat to use WebSockets for true real-time communication instead of polling.

## License
This project is open-source and available under the [MIT License](LICENSE).
*(Note: A `LICENSE` file would need to be created separately if you wish to include one.)*

## Contact
For any questions or feedback, please contact [Your Name/Email/GitHub Profile].
