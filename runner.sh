#!/bin/bash

BRANCH="main"
PID=""

PYTHON=$1
SCRIPT_ARGS="${@:2}"

trap 'shutdown' SIGINT SIGQUIT SIGTERM ERR

function shutdown() {
    echo "Exiting..."
    stop_script
    exit
}

function stop_script() {
  if [ -n "$PID" ];
  then
    kill -TERM $PID
    wait $PID
    PID=""
  fi
}

function update_script() {
    git reset -q --hard
    git checkout -q $BRANCH
    git pull -q
    $PYTHON -m pip install -q -r requirements.txt
}

while true
do

  git fetch -q origin $BRANCH

  if [ -n "$(git diff --name-only origin/$BRANCH)" ]
  then
    echo -e "\n[\033[1;32m$(date +"%d-%m-%Y %T")\033[1;0m] - New version available, updating the script!\033[0m\n"
    stop_script
    update_script
  fi

  $PYTHON runner.py $SCRIPT_ARGS & PID=$!

  sleep 60

done
