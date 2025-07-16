# Localboard - Network Clipboard

A simple web-based clipboard sharing application that allows multiple users on the same network to share text entries.

## Features

- Add text entries to a shared clipboard
- Copy entries to your local clipboard with a single click
- Delete entries you no longer need
- Real-time sharing across all users on the network
- Persistent storage of entries


## Usage

### Using Docker Compose (Recommended)

1. Clone or download this repository
2. Run the application:
   ```bash
   docker-compose up -d
   ```
3. Access the application:
   - Locally: http://localhost:5000
   - From other machines: http://YOUR_IP_ADDRESS:5000 

4. To stop the application:
   ```bash
   docker-compose down
   ```

### Using Docker (Alternative)

1. Build the image:
   ```bash
   docker build -t localboard .
   ```

2. Run the container:
   ```bash
   docker run -d -p 5000:5000 -v $(pwd)/data:/app/data localboard
   ```

### Data Persistence

The docker-compose setup automatically creates a `./data` directory on your host machine to store clipboard entries persistently. This ensures your data survives container restarts.

## Network Access

All users accessing the same server URL will see the same shared clipboard data:
- Users on the same machine: access via `localhost:5000`
- Users on other machines: access via `YOUR_SERVER_IP:5000`

The application automatically detects the correct API endpoint based on how users access it.