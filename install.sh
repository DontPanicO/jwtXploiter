#!/bin/bash


for_all=$1
script_name="jwt-crack.py"
main_path="$(realpath $0)"
tool_path=$(echo $main_path | cat | sed 's:install\.sh:jwt-crack\.py:')
req_path=$(echo $main_path | cat | sed 's:isntall\.sh:requirements\.txt:')
absolute="$(pwd)/$script_name"
bintool="jwtxpl"


if [[ $1 == "" ]]; then
    if [ ! -d "$HOME/.local/bin" ]; then
        mkdir "$HOME/bin"
        echo "export PATH=$PATH:$HOME/bin" >> $HOME/.bashrc
        bindir="$HOME/bin"
    else
        if [[ ! $PATH == *"/.local/bin"* ]]; then
            echo $PATH:/$HOME/.local/bin/ >> $HONE/.bashrc
        fi
        bindir="$HOME/.local/bin"
    fi
    chmod u+x $tool_path
    pip3 install -r $req_path
    ln -s $tool_path $bindir/$bintool
    echo "JWT cracker installed successfully. Now you can use jwtxpl <token> [OPTIONS]"


elif [[ $1 == "all" || $1 == "a" ]]; then
    if [[ $(id | grep sudo) == "" && $(id | grep "uid=0") == "" ]]; then
        echo "You have not root privileges. Only root can install the script for all users"
        exit
    fi
    chmod +x $tool_path
    pip3 install -r $req_path
    sudo ln -s $tool_path /usr/local/bin/$bintool
    echo "JWT cracker installed successfully. Now you can use jwtxpl <token> [OPTIONS]"


else
    echo "Only the options all is avaiable. Use it to install the tool for all users."
    exit

fi
