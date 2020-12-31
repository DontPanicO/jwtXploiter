#!/bin/bash

forall=$1
script_name="jwt-crack.py"
main_path="$(realpath $0)"
#main_path=$(echo $raw_path | cat | sed 's://:/:')
tool_path=$(echo $main_path | cat | sed 's:install\.sh:jwt-crack.py:')
req_path=$(echo $main_path | cat | sed 's:isntall\.sh:requirements\.txt:')
config_path=$(echo $main_path | cat | sed 's:install\.sh:config\.py:')
to_config=$(echo $main_path | cat | sed 's:install\.sh::')
absolute="$(pwd)/$scriptname"
bintool="jwtcrk"


echo "cwd = \"$to_config\"" >> $config_path

if [[ $forall == "" ]]; then
    if [ ! -d "$HOME/.local/bin" ]; then
        mkdir "$HOME/bin"
        echo "export PATH=$PATH:$HOME/bin" >> $HOME/.bashrc
        bindir="$HOME/bin"
    else
        bindir="$HOME/.local/bin"
    fi
    chmod u+x $tool_path
    pip3 install -r $req_path
    ln -s $tool_path $bindir/$bintool
    echo "JWT cracker installed successfully. Now you can use jwtcrk <token> [OPTIONS]"


elif [[ $forall == "all" || $forall == "a" ]]; then
    if [[ $(id | grep sudo) == "" ]]; then
        echo "You have not sudo privileges. Only root can install the script for all users"
        exit
    fi
    chmod +x $tool_path
    pip3 install -r $req_path
    sudo ln -s $tool_path /usr/local/bin/$bintool
    echo "JWT cracker installed successfully. Now you can use jwtcrk <token> [OPTIONS]"


else
    echo "Only the options all is avaiable. Use it to install the tool for all users."
    exit

fi
