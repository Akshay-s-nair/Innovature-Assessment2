from flask import Flask, request, send_file
import os

app = Flask(__name__)

# Configuration for file uploads
UPLOAD_FOLDER = 'D:\\Downloaded files\\'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Function to check if file extension is allowed
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Endpoint for file upload
@app.route('/upload', methods=['POST'])
def upload_file():
    """Route to Upload files."""

    if 'file' not in request.files:
        return 'No file part'
    
    file = request.files['file']
    
    if file.filename == '':
        return 'No selected file'
    
    if file and allowed_file(file.filename):
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], file.filename))
        return 'File uploaded successfully. Filename: {}'.format(file.filename)
    else:
        return 'File not allowed'

# Endpoint for generating download link
@app.route('/download', methods=['GET'])
def download_file():
    """Route to Download files."""
    file=request.form.get('file')
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file)
    if os.path.isfile(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return 'File not found'

if __name__ == '__main__':
    app.run(debug=True)
