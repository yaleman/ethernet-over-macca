#!/bin/bash
set -e

SESSION="eomacca-chat"

tmux kill-session -t "$SESSION" 2>/dev/null || true
tmux new-session -d -s "$SESSION" -x 200 -y 50


tmux send-keys -t "$SESSION" "clear && uv run --directory $(pwd) just server-tcp chat" Enter
sleep 2

# split it vertically and run tcpdump in the bottom pane
tmux split-window -v -t "$SESSION" -p 50
tmux select-pane -t "$SESSION":0.1
tmux send-keys -t "$SESSION" "clear && tcpdump -i lo0 -nn 'port 9999'" Enter

# set up the client
tmux select-pane -t "$SESSION":0.0
tmux split-window -h -t "$SESSION"
tmux send-keys -t "$SESSION" "clear && uv run --directory $(pwd) just demo-chat" Enter
sleep 1

tmux send-keys -t "$SESSION:0.1" "Hello world" Enter

tmux attach-session -t "$SESSION"
