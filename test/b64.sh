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

# Test vectors from RFC 4648
echo -n "" > random_data
tst=$(./b64 0 "random_data")
ref=""
check $ref $tst 

echo -n "f" > random_data
tst=$(./b64 1 "random_data")
ref="Zg"
check $ref $tst 

echo -n "fo" > random_data
tst=$(./b64 2 "random_data")
ref="Zm8"
check $ref $tst 

echo -n "foo" > random_data
tst=$(./b64 3 "random_data")
ref="Zm9v"
check $ref $tst 

echo -n "foob" > random_data
tst=$(./b64 4 "random_data")
ref="Zm9vYg"
check $ref $tst 

# Randomized test
for i in {0..128}; do
        nbytes=$(echo -n $(($RANDOM % 512)))
        echo -n $nbytes > nbytes
        cat /dev/random | head -c$nbytes > random_data
        #echo $RANDOM | base64 | head -c$nbytes > random_data

        ref=$(base64 -w0 random_data | tr '+/' '-_' | tr -d '=')
        tst=$(./b64 "$nbytes" "random_data")

        check "$ref" "$tst"
done
rm random_data
rm nbytes
if [[ $fail -gt 0 ]]; then
        echo -e "$RED $fail of $total TESTS FAILED.$RESET"
        exit -1
else 
        echo -e "$GREEN $total of $total TESTS PASSED SUCCESSFULLY.$RESET"
        exit 0
fi
