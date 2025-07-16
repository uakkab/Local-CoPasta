# app.py
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import json
import os
import uuid

# Initialize Flask app, specifying the static folder to serve index.html
app = Flask(__name__, static_folder='.') # Set static_folder to current directory
CORS(app) # Enable CORS for all routes, allowing frontend to access

# Define the path for the JSON file to store clipboard data
DATA_FILE = os.environ.get('DATA_FILE', 'clipboard_data.json')

# --- Helper Functions for Data Persistence ---

def load_clipboard_data():
    """Loads clipboard data from the JSON file."""
    print(f"[DEBUG] Loading data from: {os.path.abspath(DATA_FILE)}")
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, 'r') as f:
            try:
                data = json.load(f)
                print(f"[DEBUG] Loaded {len(data)} entries from data file")
                return data
            except json.JSONDecodeError:
                # Handle empty or corrupted JSON file
                print("[DEBUG] JSON decode error, returning empty list")
                return []
    print("[DEBUG] Data file doesn't exist, returning empty list")
    return []

def save_clipboard_data(data):
    """Saves clipboard data to the JSON file."""
    print(f"[DEBUG] Saving {len(data)} entries to: {os.path.abspath(DATA_FILE)}")
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)
    print(f"[DEBUG] Data saved successfully")

# --- Flask Routes ---

@app.route('/')
def index():
    """Serves the main HTML file."""
    # Use send_from_directory to serve index.html from the root of the static folder
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/clipboard', methods=['GET'])
def get_clipboard():
    """
    Retrieves all clipboard entries.
    Returns:
        JSON: A list of clipboard entry objects.
    """
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
    print(f"[DEBUG] GET /clipboard request from IP: {client_ip}")
    data = load_clipboard_data()
    print(f"[DEBUG] Returning {len(data)} entries to client")
    return jsonify(data)

@app.route('/clipboard', methods=['POST'])
def add_clipboard_entry():
    """
    Adds a new clipboard entry.
    Expects JSON payload: {"content": "your text here"}
    Returns:
        JSON: The newly added clipboard entry.
    """
    client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR', 'unknown'))
    new_entry_content = request.json.get('content')
    print(f"[DEBUG] POST /clipboard request from IP: {client_ip}, content: {new_entry_content[:50]}...")
    
    if not new_entry_content:
        return jsonify({"error": "Content is required"}), 400

    data = load_clipboard_data()
    new_entry = {
        "id": str(uuid.uuid4()), # Generate a unique ID for the entry
        "content": new_entry_content
    }
    data.append(new_entry)
    save_clipboard_data(data)
    print(f"[DEBUG] Added new entry with ID: {new_entry['id']}")
    return jsonify(new_entry), 201

@app.route('/clipboard/<string:entry_id>', methods=['DELETE'])
def delete_clipboard_entry(entry_id):
    """
    Deletes a clipboard entry by its ID.
    Args:
        entry_id (str): The ID of the entry to delete.
    Returns:
        JSON: A success message or error if not found.
    """
    data = load_clipboard_data()
    initial_len = len(data)
    # Filter out the entry with the matching ID
    data = [entry for entry in data if entry['id'] != entry_id]

    if len(data) == initial_len:
        return jsonify({"error": "Entry not found"}), 404

    save_clipboard_data(data)
    return jsonify({"message": "Entry deleted successfully"}), 200

if __name__ == '__main__':
    # Ensure the data file exists on startup
    if not os.path.exists(DATA_FILE):
        save_clipboard_data([]) # Create an empty JSON array if file doesn't exist
    app.run(debug=True, host='0.0.0.0', port=5000)
