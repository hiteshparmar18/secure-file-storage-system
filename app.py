from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash, jsonify
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
import os
import qrcode

app = Flask(__name__)
app.secret_key = "your_secret_key"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Generate or load encryption key
KEY_FILE = "secret.key"

def load_key():
    """Load the encryption key from a file, or generate a new one if it doesn't exist."""
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)
    else:
        with open(KEY_FILE, "rb") as key_file:
            key = key_file.read()
    return key

encryption_key = load_key()
cipher = Fernet(encryption_key)

@app.route('/')
def home():
    """Home page or dashboard redirect based on user login status."""
    if 'user' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login route with validation."""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username and password:
            session['user'] = username
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password!", "danger")
    return render_template('login.html', title='Login - Secure File Storage')

@app.route('/logout')
def logout():
    """Log out and clear the session."""
    session.pop('user', None)
    flash("Logged out successfully!", "info")
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    """Display the dashboard with uploaded files information."""
    if 'user' not in session:
        return redirect(url_for('login'))

    files = os.listdir(app.config['UPLOAD_FOLDER'])
    file_info = []
    total_size = 0

    for file in files:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file)
        file_size = round(os.path.getsize(file_path) / 1024, 2)  # Convert to KB
        total_size += file_size

        # Determine file type
        file_type = "other"
        if file.endswith(".pdf"):
            file_type = "pdf"
        elif file.endswith((".png", ".jpg", ".jpeg")):
            file_type = "image"
        elif file.endswith(".txt"):
            file_type = "text"

        encrypted = file.endswith(".enc")
        file_info.append({
            "name": file,
            "type": file_type,
            "size": f"{file_size} KB",
            "encrypted": encrypted
        })

    return render_template('dashboard.html', files=file_info, user=session['user'], total_size=total_size, title='Dashboard - Secure File Storage')

@app.route('/upload', methods=['POST'])
def upload_file():
    """Handle file upload and encryption."""
    if 'file' not in request.files:
        flash("No file selected!", "danger")
        return redirect(url_for('dashboard'))

    files = request.files.getlist('file')
    for file in files:
        if file.filename == '':
            continue
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Encrypt the file and save it with .enc extension
        with open(file_path, "rb") as f:
            encrypted_data = cipher.encrypt(f.read())
        encrypted_path = file_path + ".enc"
        with open(encrypted_path, "wb") as f:
            f.write(encrypted_data)

        # Remove the original unencrypted file
        os.remove(file_path)

    flash("Files uploaded and encrypted successfully!", "success")
    return redirect(url_for('dashboard'))

@app.route('/download/<filename>')
def download_file(filename):
    """Download a file."""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(filename))
    if not os.path.exists(file_path):
        flash("File not found!", "danger")
        return redirect(url_for('dashboard'))
    return send_file(file_path, as_attachment=True)

@app.route('/decrypt/<filename>', methods=['GET', 'POST'])
def decrypt_file(filename):
    """Decrypt a file and provide download options based on file type."""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if not filename.endswith(".enc"):
        flash("Invalid file format!", "danger")
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        # Decrypt the file
        with open(file_path, "rb") as f:
            decrypted_data = cipher.decrypt(f.read())
        decrypted_path = file_path.replace(".enc", "_decrypted")

        with open(decrypted_path, "wb") as f:
            f.write(decrypted_data)

        # Send the file based on selected type
        selected_type = request.form.get('file_type')
        if selected_type == "pdf":
            return send_file(decrypted_path, as_attachment=True, mimetype='application/pdf')
        elif selected_type == "image":
            return send_file(decrypted_path, as_attachment=True, mimetype='image/png')
        elif selected_type == "text":
            return send_file(decrypted_path, as_attachment=True, mimetype='text/plain')
        else:
            flash("Invalid file type selected!", "danger")
            return redirect(url_for('dashboard'))

    return render_template('decrypt.html', filename=filename)

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    """Delete a file from the server."""
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash("File deleted successfully!", "success")
    else:
        flash("File not found!", "danger")
    return redirect(url_for('dashboard'))

@app.route('/generate_qr/<filename>')
def generate_qr(filename):
    """Generate a QR code for downloading the file."""
    filename = secure_filename(filename)
    file_url = url_for('download_file', filename=filename, _external=True)
    qr = qrcode.make(file_url)
    qr_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.png")
    qr.save(qr_path)
    return send_file(qr_path, mimetype='image/png')

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
