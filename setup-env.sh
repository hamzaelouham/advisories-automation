#!/bin/bash
set -x
echo "**** checking for environment setup ****"

if python3 --version &>/dev/null; then
    echo "Python is already installed!"
    python_version=$(python3 --version)
    echo "Python version: $python_version"
else
    echo "Installing Python & pip ..."
    apt update -y
    apt install python3 python3-pip -y
fi

venv_dir=venv

if [ -d "$venv_dir" ]; then
    echo "**** environment already setup ****"
else
    echo "installing and creating venv & installing packages!"
    python3 -m venv "$venv_dir"
    source "$venv_dir/bin/activate"
    echo "upgrading pip!"
    python3 -m pip install --upgrade pip > /dev/null 2>&1
    if [ -f 'requirements.txt' ];then
       python3 -m pip install -r requirements.txt
    else
       echo "Please, list all packages in requirements.txt"
       exit 0 
    fi
fi








