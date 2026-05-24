#!/usr/bin/env fish

source (dirname (status filename))/yint.fish

set -l cmd $argv[1]
set -e argv[1]

switch $cmd
    case derive
        yint_derive $argv
    case build-request
        yint_build_request $argv
    case open-request
        yint_open_request $argv
    case build-response
        yint_build_response $argv
    case open-response
        yint_open_response $argv
    case '*'
        yint_die 'usage: yint-cli.fish derive|build-request|open-request|build-response|open-response ...' 2
end
