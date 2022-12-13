#!/bin/bash

RED="\e[41m\e[30m"
GREEN="\e[32m"
RESET="\e[0m"
YELLOW="\e[1m\e[1;33m"

total=0
fail=0

pass() {
        echo -e "$GREEN TEST $total: PASS $RESET"
}

fail() {
        echo -e "$RED TEST $total: FAIL$RESET "
        printf "$YELLOW Expected:$RESET %s\n$YELLOW Got:     $RESET %s\n" "$1" "$2"
        exit -1        
}

check(){
        let total++
        if [ "$1" == "$2" ]; then
                pass "$2"
        else
                fail "$1" "$2"
                let fail++
        fi   
}

valgrind_cmd="valgrind --error-exitcode=255 --exit-on-first-error=yes --leak-check=full --show-leak-kinds=all"

$valgrind_cmd ./chal 0
tst=$?
ref=0
check "$ref" "$tst" 


