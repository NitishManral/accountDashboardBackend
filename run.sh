#!/bin/bash
# Find the process ID of the process listening on port 3000
PID=$(lsof -t -i:3000)

# If a process is found, kill it
if [ -n "$PID" ]; then
    echo "Killing process on port 3000 with PID: $PID"
    kill -9 $PID
else
    echo "No process running on port 3000"
fi
# Run node index.js
echo "Starting Node.js application"
npm run tsc
node dist/index.js