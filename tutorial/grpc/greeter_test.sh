#!/bin/bash

# Start the greeter_server in the background
./greeter_server &
server_pid=$!

# Run the greeter_client
./greeter_client

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