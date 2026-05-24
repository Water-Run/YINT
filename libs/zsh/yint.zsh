#!/usr/bin/env zsh

# Zsh 5+ 函数库. 所有 body 与 plaintext 参数均为小写 hex.

YINT_ZSH_DIR="${${(%):-%x}:A:h}"
: ${YINT_CORE:="$YINT_ZSH_DIR/../../core/bin/yint"}
: ${YINT_TIME_WINDOW:=300}
: ${YINT_NONCE_FILE:="${TMPDIR:-/tmp}/yint-nonces.txt"}

yint_die() {
    print -u2 -- "$1"
    return ${2:-1}
}

yint_now() {
    date +%s
}

yint_is_lower_hex() {
    local value="$1" len="$2"
    [[ ${#value} -eq $len && "$value" =~ '^[0-9a-f]+$' ]]
}

yint_derive() {
    "$YINT_CORE" derive "$1"
}

yint_keys() {
    local derived
    derived="$(yint_derive "$1")" || return
    YINT_K_ENC="${derived%% *}"
    YINT_K_MAC="${derived##* }"
}

yint_build_request() {
    local master_hex="$1" method="${2:u}" uri="$3" plaintext_hex="$4"
    local timestamp nonce iv body_hex sign
    yint_keys "$master_hex" || return
    timestamp="$(yint_now)"
    nonce="$("$YINT_CORE" random 16)" || return
    iv="$("$YINT_CORE" random 16)" || return
    body_hex="$(print -rn -- "$plaintext_hex" | "$YINT_CORE" build-body "$YINT_K_ENC" "$iv" -)" || return
    sign="$(print -rn -- "$body_hex" | "$YINT_CORE" sign-req "$YINT_K_MAC" "$method" "$uri" "$timestamp" "$nonce" -)" || return
    print -r -- "timestamp=$timestamp"
    print -r -- "nonce=$nonce"
    print -r -- "sign=$sign"
    print -r -- "body_hex=$body_hex"
}

yint_build_response() {
    local master_hex="$1" status_code="$2" req_nonce="$3" plaintext_hex="$4"
    local timestamp nonce iv body_hex sign
    yint_keys "$master_hex" || return
    timestamp="$(yint_now)"
    nonce="$("$YINT_CORE" random 16)" || return
    iv="$("$YINT_CORE" random 16)" || return
    body_hex="$(print -rn -- "$plaintext_hex" | "$YINT_CORE" build-body "$YINT_K_ENC" "$iv" -)" || return
    sign="$(print -rn -- "$body_hex" | "$YINT_CORE" sign-resp "$YINT_K_MAC" "$status_code" "$timestamp" "$nonce" "$req_nonce" -)" || return
    print -r -- "timestamp=$timestamp"
    print -r -- "nonce=$nonce"
    print -r -- "sign=$sign"
    print -r -- "body_hex=$body_hex"
}

yint_cleanup_nonce_file() {
    local now="$1" file="${2:-$YINT_NONCE_FILE}" tmp nonce expire
    mkdir -p -- "${file:h}" || return
    tmp="${file}.$$"
    : > "$tmp" || return
    if [[ -f "$file" ]]; then
        while read -r nonce expire; do
            [[ -n "$nonce" && "$expire" == <-> && "$expire" -ge "$now" ]] && print -r -- "$nonce $expire" >> "$tmp"
        done < "$file"
    fi
    mv -- "$tmp" "$file"
}

yint_nonce_seen() {
    local nonce="$1" file="${2:-$YINT_NONCE_FILE}"
    [[ -f "$file" ]] && grep -Eq "^${nonce} " "$file"
}

yint_open_request() {
    local master_hex="$1" method="${2:u}" uri="$3" timestamp="$4" nonce="$5" sign="$6" body_hex="$7"
    local time_window="${8:-$YINT_TIME_WINDOW}" nonce_file="${9:-$YINT_NONCE_FILE}" now delta out
    yint_is_lower_hex "$nonce" 32 || yint_die 'bad yint headers' 400 || return
    yint_is_lower_hex "$sign" 64 || yint_die 'bad yint headers' 400 || return
    [[ "$timestamp" == <-> ]] || yint_die 'bad yint headers' 400 || return
    yint_keys "$master_hex" || return
    now="$(yint_now)"
    (( delta = now > timestamp ? now - timestamp : timestamp - now ))
    (( delta <= time_window )) || yint_die 'unauthorized' 401 || return
    yint_cleanup_nonce_file "$now" "$nonce_file" || return
    yint_nonce_seen "$nonce" "$nonce_file" && yint_die 'unauthorized' 401 && return
    out="$(print -rn -- "$body_hex" | "$YINT_CORE" verify-req "$YINT_K_MAC" "$method" "$uri" "$timestamp" "$nonce" "$sign" -)" || yint_die 'unauthorized' 401 || return
    [[ "$out" == OK ]] || yint_die 'unauthorized' 401 || return
    print -r -- "$nonce $(( timestamp + time_window ))" >> "$nonce_file"
    print -rn -- "$body_hex" | "$YINT_CORE" decrypt-body "$YINT_K_ENC" -
}

yint_open_response() {
    local master_hex="$1" status_code="$2" req_nonce="$3" timestamp="$4" nonce="$5" sign="$6" body_hex="$7"
    local time_window="${8:-$YINT_TIME_WINDOW}" now delta out
    yint_is_lower_hex "$req_nonce" 32 || yint_die 'bad yint headers' 400 || return
    yint_is_lower_hex "$nonce" 32 || yint_die 'bad yint headers' 400 || return
    yint_is_lower_hex "$sign" 64 || yint_die 'bad yint headers' 400 || return
    [[ "$timestamp" == <-> ]] || yint_die 'bad yint headers' 400 || return
    yint_keys "$master_hex" || return
    now="$(yint_now)"
    (( delta = now > timestamp ? now - timestamp : timestamp - now ))
    (( delta <= time_window )) || yint_die 'unauthorized' 401 || return
    out="$(print -rn -- "$body_hex" | "$YINT_CORE" verify-resp "$YINT_K_MAC" "$status_code" "$timestamp" "$nonce" "$req_nonce" "$sign" -)" || yint_die 'unauthorized' 401 || return
    [[ "$out" == OK ]] || yint_die 'unauthorized' 401 || return
    print -rn -- "$body_hex" | "$YINT_CORE" decrypt-body "$YINT_K_ENC" -
}

if [[ ":${ZSH_EVAL_CONTEXT:-}:" != *:file:* ]]; then
    cmd="${1:-}"; shift || true
    case "$cmd" in
        derive) yint_derive "$@" ;;
        build-request) yint_build_request "$@" ;;
        open-request) yint_open_request "$@" ;;
        build-response) yint_build_response "$@" ;;
        open-response) yint_open_response "$@" ;;
        *) yint_die 'usage: yint.zsh derive|build-request|open-request|build-response|open-response ...' 2 ;;
    esac
fi
