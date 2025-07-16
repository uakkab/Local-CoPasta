# Dockerfile

# Use a lightweight Python base image
FROM python:3.9-slim-buster

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Flask application and the frontend HTML file
COPY app.py .
COPY index.html .

# Create data directory for persistent storage
RUN mkdir -p /app/data

# Ensure the data file is created if it doesn't exist (or copy an empty one)
# This ensures the app doesn't crash on first run if no data file is present
RUN touch /app/data/clipboard_data.json

# Expose the port Flask will run on
EXPOSE 5000

# Command to run the Flask application
# Use a production-ready WSGI server like Gunicorn for robustness in production,
# but for a minimal footprint and simple setup, Flask's built-in server is fine.
# For demonstration, we'll use Flask's built-in server.
CMD ["python", "app.py"]
