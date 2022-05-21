#!/bin/bash

BRANCH="main"
PID=""

trap 'shutdown' SIGINT SIGQUIT SIGTERM

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
    $1 -m pip install -q -r requirements.txt
}

while true
do

  git fetch -q origin $BRANCH

  if [ -n "$(git diff --name-only origin/$BRANCH)" ]
  then
    echo "New version available, updating the script..."
    stop_script
    update_script
  fi

  $1 runner.py "${@:1}" & PID=$!

  sleep 60

done
