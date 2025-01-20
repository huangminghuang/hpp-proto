#!/bin/bash

# Function to find an available port (cross-platform)
find_available_port() {
  local port=50051  # Starting port number
  while true; do
    if lsof -i :$port > /dev/null 2>&1; then
      ((port++))
    else
      echo $port
      break
    fi
  done
}

# Find an available port
port=$(find_available_port)
echo "Using port: $port"

# Start the greeter_server in the background
./greeter_server localhost:$port &
server_pid=$!
sleep 1
# Run the greeter_client
./greeter_client localhost:$port

# Get the client's exit code
client_exit_code=$?

# Wait for the server to finish
wait $server_pid
server_exit_code=$?

# Check if the server exited with 0
if [[ $client_exit_code -eq 0 && $server_exit_code -eq 0  ]]; then
  exit 0
else
  echo "Error: Client returned: $client_exit_code, Server returned: $server_exit_code"
  exit 1
fi