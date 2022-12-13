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

tst=$(./string 0)
ref=$(echo -e "<empty list>")
check "$ref" "$tst" 

tst=$(./string 1)
ref=$(echo -e "[0] first_entry 11")
check "$ref" "$tst" 

tst=$(./string 2)
ref=$(echo -e "[0] first_entry 11\n[1] second_entry 12\n[2] third_entry 11\n[3] 123 3\n[4]  0\n[5] last### 7")
check "$ref" "$tst" 

tst=$(./string 3)
ref=$(echo -e "Removed second_entry\nRemoved third_entry\nRemoved first_entry\n<empty list>")
check "$ref" "$tst" 

tst=$(./string 4)
ref=$(echo -e "[0] first_entry 11\n[1] second_entry 12\n[2] third_entry 11\n")
check "$ref" "$tst" 

