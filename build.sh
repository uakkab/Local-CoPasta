#!/bin/bash
# Build script for Linux/macOS - No CGO required

echo "Building Local Pastebin..."
echo ""

# Clean any previous builds
rm -f pastebin

# Update dependencies
echo "Updating dependencies..."
go mod tidy

# Build the binary
echo "Building binary..."
go build -o pastebin main.go

if [ $? -eq 0 ]; then
    echo ""
    echo "✓ Build successful!"
    echo "Binary created: pastebin"
    echo ""
    echo "To run the application:"
    echo "  ./pastebin"
    echo ""
    echo "The server will start on http://localhost:8080"

    # Make executable
    chmod +x pastebin
else
    echo ""
    echo "✗ Build failed. Please check the error messages above."
    exit 1
fi
