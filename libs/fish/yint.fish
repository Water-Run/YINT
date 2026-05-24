#!/usr/bin/env fish

# Fish 3+ 函数库. 所有 body 与 plaintext 参数均为小写 hex.

set -q YINT_CORE; or set -gx YINT_CORE (status dirname)/../../core/bin/yint
set -q YINT_TIME_WINDOW; or set -gx YINT_TIME_WINDOW 300
set -q YINT_NONCE_FILE; or set -gx YINT_NONCE_FILE (string join / (set -q TMPDIR; and echo $TMPDIR; or echo /tmp) yint-nonces.txt)

function yint_die
    echo $argv[1] >&2
    return (test (count $argv) -ge 2; and echo $argv[2]; or echo 1)
end

function yint_now
    date +%s
end

function yint_is_lower_hex
    set -l value $argv[1]
    set -l len $argv[2]
    test (string length -- $value) -eq $len; and string match -rq '^[0-9a-f]+$' -- $value
end

function yint_derive
    "$YINT_CORE" derive $argv[1]
end

function yint_keys
    set -l derived (yint_derive $argv[1]); or return
    set -g YINT_K_ENC (string split ' ' -- $derived)[1]
    set -g YINT_K_MAC (string split ' ' -- $derived)[2]
end

function yint_build_request
    set -l master_hex $argv[1]
    set -l method (string upper -- $argv[2])
    set -l uri $argv[3]
    set -l plaintext_hex $argv[4]
    yint_keys $master_hex; or return
    set -l timestamp (yint_now)
    set -l nonce ("$YINT_CORE" random 16); or return
    set -l iv ("$YINT_CORE" random 16); or return
    set -l body_hex (printf '%s' $plaintext_hex | "$YINT_CORE" build-body $YINT_K_ENC $iv -); or return
    set -l sign (printf '%s' $body_hex | "$YINT_CORE" sign-req $YINT_K_MAC $method $uri $timestamp $nonce -); or return
    printf 'timestamp=%s\nnonce=%s\nsign=%s\nbody_hex=%s\n' $timestamp $nonce $sign $body_hex
end

function yint_build_response
    set -l master_hex $argv[1]
    set -l status_code $argv[2]
    set -l req_nonce $argv[3]
    set -l plaintext_hex $argv[4]
    yint_keys $master_hex; or return
    set -l timestamp (yint_now)
    set -l nonce ("$YINT_CORE" random 16); or return
    set -l iv ("$YINT_CORE" random 16); or return
    set -l body_hex (printf '%s' $plaintext_hex | "$YINT_CORE" build-body $YINT_K_ENC $iv -); or return
    set -l sign (printf '%s' $body_hex | "$YINT_CORE" sign-resp $YINT_K_MAC $status_code $timestamp $nonce $req_nonce -); or return
    printf 'timestamp=%s\nnonce=%s\nsign=%s\nbody_hex=%s\n' $timestamp $nonce $sign $body_hex
end

function yint_cleanup_nonce_file
    set -l now $argv[1]
    set -l file $argv[2]
    test -n "$file"; or set file $YINT_NONCE_FILE
    mkdir -p (dirname -- $file); or return
    set -l tmp "$file.$fish_pid"
    true > $tmp; or return
    if test -f $file
        while read -l nonce expire
            if test -n "$nonce"; and string match -rq '^[0-9]+$' -- "$expire"; and test $expire -ge $now
                printf '%s %s\n' $nonce $expire >> $tmp
            end
        end < $file
    end
    mv -- $tmp $file
end

function yint_nonce_seen
    set -l nonce $argv[1]
    set -l file $argv[2]
    test -n "$file"; or set file $YINT_NONCE_FILE
    test -f $file; and grep -Eq "^$nonce " $file
end

function yint_open_request
    set -l master_hex $argv[1]
    set -l method (string upper -- $argv[2])
    set -l uri $argv[3]
    set -l timestamp $argv[4]
    set -l nonce $argv[5]
    set -l sign $argv[6]
    set -l body_hex $argv[7]
    set -l time_window (test (count $argv) -ge 8; and echo $argv[8]; or echo $YINT_TIME_WINDOW)
    set -l nonce_file (test (count $argv) -ge 9; and echo $argv[9]; or echo $YINT_NONCE_FILE)
    yint_is_lower_hex $nonce 32; or yint_die 'bad yint headers' 400; or return
    yint_is_lower_hex $sign 64; or yint_die 'bad yint headers' 400; or return
    string match -rq '^[0-9]+$' -- $timestamp; or yint_die 'bad yint headers' 400; or return
    yint_keys $master_hex; or return
    set -l now (yint_now)
    set -l delta (math "abs($now - $timestamp)")
    test $delta -le $time_window; or yint_die 'unauthorized' 401; or return
    yint_cleanup_nonce_file $now $nonce_file; or return
    yint_nonce_seen $nonce $nonce_file; and yint_die 'unauthorized' 401; and return
    set -l out (printf '%s' $body_hex | "$YINT_CORE" verify-req $YINT_K_MAC $method $uri $timestamp $nonce $sign -); or yint_die 'unauthorized' 401; or return
    test "$out" = OK; or yint_die 'unauthorized' 401; or return
    printf '%s %s\n' $nonce (math "$timestamp + $time_window") >> $nonce_file
    printf '%s' $body_hex | "$YINT_CORE" decrypt-body $YINT_K_ENC -
end

function yint_open_response
    set -l master_hex $argv[1]
    set -l status_code $argv[2]
    set -l req_nonce $argv[3]
    set -l timestamp $argv[4]
    set -l nonce $argv[5]
    set -l sign $argv[6]
    set -l body_hex $argv[7]
    set -l time_window (test (count $argv) -ge 8; and echo $argv[8]; or echo $YINT_TIME_WINDOW)
    yint_is_lower_hex $req_nonce 32; or yint_die 'bad yint headers' 400; or return
    yint_is_lower_hex $nonce 32; or yint_die 'bad yint headers' 400; or return
    yint_is_lower_hex $sign 64; or yint_die 'bad yint headers' 400; or return
    string match -rq '^[0-9]+$' -- $timestamp; or yint_die 'bad yint headers' 400; or return
    yint_keys $master_hex; or return
    set -l now (yint_now)
    set -l delta (math "abs($now - $timestamp)")
    test $delta -le $time_window; or yint_die 'unauthorized' 401; or return
    set -l out (printf '%s' $body_hex | "$YINT_CORE" verify-resp $YINT_K_MAC $status_code $timestamp $nonce $req_nonce $sign -); or yint_die 'unauthorized' 401; or return
    test "$out" = OK; or yint_die 'unauthorized' 401; or return
    printf '%s' $body_hex | "$YINT_CORE" decrypt-body $YINT_K_ENC -
end
