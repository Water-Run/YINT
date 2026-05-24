#!/usr/bin/env bash

# Bash 4+ 函数库. 所有 body 与 plaintext 参数均为小写 hex.

YINT_BASH_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
: "${YINT_CORE:=$YINT_BASH_DIR/../../core/bin/yint}"
: "${YINT_TIME_WINDOW:=300}"
: "${YINT_NONCE_FILE:=${TMPDIR:-/tmp}/yint-nonces.txt}"

yint_die() {
    printf '%s\n' "$1" >&2
    return "${2:-1}"
}

yint_now() {
    date +%s
}

yint_is_lower_hex() {
    local value="$1" len="$2"
    [[ ${#value} -eq $len && "$value" =~ ^[0-9a-f]+$ ]]
}

yint_derive() {
    local master_hex="$1"
    "$YINT_CORE" derive "$master_hex"
}

yint_keys() {
    local master_hex="$1"
    local derived
    derived="$(yint_derive "$master_hex")" || return
    YINT_K_ENC="${derived%% *}"
    YINT_K_MAC="${derived##* }"
}

yint_build_request() {
    local master_hex="$1" method="$2" uri="$3" plaintext_hex="$4"
    local timestamp nonce iv body_hex sign
    yint_keys "$master_hex" || return
    method="${method^^}"
    timestamp="$(yint_now)"
    nonce="$("$YINT_CORE" random 16)" || return
    iv="$("$YINT_CORE" random 16)" || return
    body_hex="$(printf '%s' "$plaintext_hex" | "$YINT_CORE" build-body "$YINT_K_ENC" "$iv" -)" || return
    sign="$(printf '%s' "$body_hex" | "$YINT_CORE" sign-req "$YINT_K_MAC" "$method" "$uri" "$timestamp" "$nonce" -)" || return
    printf 'timestamp=%s\nnonce=%s\nsign=%s\nbody_hex=%s\n' "$timestamp" "$nonce" "$sign" "$body_hex"
}

yint_build_response() {
    local master_hex="$1" status="$2" req_nonce="$3" plaintext_hex="$4"
    local timestamp nonce iv body_hex sign
    yint_keys "$master_hex" || return
    timestamp="$(yint_now)"
    nonce="$("$YINT_CORE" random 16)" || return
    iv="$("$YINT_CORE" random 16)" || return
    body_hex="$(printf '%s' "$plaintext_hex" | "$YINT_CORE" build-body "$YINT_K_ENC" "$iv" -)" || return
    sign="$(printf '%s' "$body_hex" | "$YINT_CORE" sign-resp "$YINT_K_MAC" "$status" "$timestamp" "$nonce" "$req_nonce" -)" || return
    printf 'timestamp=%s\nnonce=%s\nsign=%s\nbody_hex=%s\n' "$timestamp" "$nonce" "$sign" "$body_hex"
}

yint_cleanup_nonce_file() {
    local now="$1" file="${2:-$YINT_NONCE_FILE}"
    local tmp nonce expire
    mkdir -p -- "$(dirname -- "$file")" || return
    tmp="${file}.$$"
    : > "$tmp" || return
    if [[ -f "$file" ]]; then
        while read -r nonce expire; do
            [[ -n "$nonce" && "$expire" =~ ^[0-9]+$ && "$expire" -ge "$now" ]] && printf '%s %s\n' "$nonce" "$expire" >> "$tmp"
        done < "$file"
    fi
    mv -- "$tmp" "$file"
}

yint_nonce_seen() {
    local nonce="$1" file="${2:-$YINT_NONCE_FILE}"
    [[ -f "$file" ]] && grep -Eq "^${nonce} " "$file"
}

yint_open_request() {
    local master_hex="$1" method="$2" uri="$3" timestamp="$4" nonce="$5" sign="$6" body_hex="$7"
    local time_window="${8:-$YINT_TIME_WINDOW}" nonce_file="${9:-$YINT_NONCE_FILE}"
    local now delta out
    yint_is_lower_hex "$nonce" 32 || yint_die 'bad yint headers' 400 || return
    yint_is_lower_hex "$sign" 64 || yint_die 'bad yint headers' 400 || return
    [[ "$timestamp" =~ ^[0-9]+$ ]] || yint_die 'bad yint headers' 400 || return
    yint_keys "$master_hex" || return
    method="${method^^}"
    now="$(yint_now)"
    delta=$(( now > timestamp ? now - timestamp : timestamp - now ))
    (( delta <= time_window )) || yint_die 'unauthorized' 401 || return
    yint_cleanup_nonce_file "$now" "$nonce_file" || return
    yint_nonce_seen "$nonce" "$nonce_file" && yint_die 'unauthorized' 401 && return
    out="$(printf '%s' "$body_hex" | "$YINT_CORE" verify-req "$YINT_K_MAC" "$method" "$uri" "$timestamp" "$nonce" "$sign" -)" || yint_die 'unauthorized' 401 || return
    [[ "$out" == OK ]] || yint_die 'unauthorized' 401 || return
    printf '%s %s\n' "$nonce" "$(( timestamp + time_window ))" >> "$nonce_file"
    printf '%s' "$body_hex" | "$YINT_CORE" decrypt-body "$YINT_K_ENC" -
}

yint_open_response() {
    local master_hex="$1" status="$2" req_nonce="$3" timestamp="$4" nonce="$5" sign="$6" body_hex="$7"
    local time_window="${8:-$YINT_TIME_WINDOW}" now delta out
    yint_is_lower_hex "$req_nonce" 32 || yint_die 'bad yint headers' 400 || return
    yint_is_lower_hex "$nonce" 32 || yint_die 'bad yint headers' 400 || return
    yint_is_lower_hex "$sign" 64 || yint_die 'bad yint headers' 400 || return
    [[ "$timestamp" =~ ^[0-9]+$ ]] || yint_die 'bad yint headers' 400 || return
    yint_keys "$master_hex" || return
    now="$(yint_now)"
    delta=$(( now > timestamp ? now - timestamp : timestamp - now ))
    (( delta <= time_window )) || yint_die 'unauthorized' 401 || return
    out="$(printf '%s' "$body_hex" | "$YINT_CORE" verify-resp "$YINT_K_MAC" "$status" "$timestamp" "$nonce" "$req_nonce" "$sign" -)" || yint_die 'unauthorized' 401 || return
    [[ "$out" == OK ]] || yint_die 'unauthorized' 401 || return
    printf '%s' "$body_hex" | "$YINT_CORE" decrypt-body "$YINT_K_ENC" -
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    cmd="${1:-}"; shift || true
    case "$cmd" in
        derive) yint_derive "$@" ;;
        build-request) yint_build_request "$@" ;;
        open-request) yint_open_request "$@" ;;
        build-response) yint_build_response "$@" ;;
        open-response) yint_open_response "$@" ;;
        *) yint_die 'usage: yint.sh derive|build-request|open-request|build-response|open-response ...' 2 ;;
    esac
fi
