#!/bin/bash --posix

# This script may need some adjustments to work on a given system.
# Also, please be advised that 'bash' (not 'sh') must be used.

# Copyright (c) 2020-2021 IETF Trust, Kent Watsen, and Erik
# Auerswald.  All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#   * Redistributions in binary form must reproduce the above
#     copyright notice, this list of conditions and the following
#     disclaimer in the documentation and/or other materials
#     provided with the distribution.
#
#   * Neither the name of Internet Society, IETF or IETF Trust, nor
#     the names of specific contributors, may be used to endorse or
#     promote products derived from this software without specific
#     prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

print_usage() {
  printf "\n"
  printf "Folds or unfolds the input text file according to"
  printf " RFC 8792.\n"
  printf "\n"
  printf "Usage: rfcfold [-h] [-V] [-d] [-q] [-s <strategy>]"
  printf " [-c <col>] [-r] -i <infile> -o <outfile>\n"
  printf "\n"
  printf "  -s: strategy to use, '1' or '2' (default: try 1,"
  printf " else 2)\n"
  printf "  -c: column to fold on (default: 69)\n"
  printf "  -r: reverses the operation\n"
  printf "  -i: the input filename\n"
  printf "  -o: the output filename\n"
  printf "  -d: show debug messages (unless -q is given)\n"
  printf "  -q: quiet (suppress error and debug messages)\n"
  printf "  -h: show this message\n"
  printf "  -V: print version information\n"
  printf "\n"
  printf "Exit status code: 1 on error, 0 on success, 255 on no-op."
  printf "\n\n"
}

print_version() {
  printf -- '%s version %s\n' "$prog_name" "$prog_version"
}

# global vars, do not edit
strategy=0 # auto
debug=0
quiet=0
reversed=0
infile=""
outfile=""
maxcol=69  # default, may be overridden by param
col_gvn=0  # maxcol overridden?
hdr_txt_1="NOTE: '\\' line wrapping per RFC 8792"
hdr_txt_2="NOTE: '\\\\' line wrapping per RFC 8792"
temp_dir=""
temp_infile=""
prog_name='rfcfold'
prog_version='1.3.0'

# functions for diagnostic messages
prog_msg() {
  if [[ "$quiet" -eq 0 ]]; then
    local severity
    severity=$1
    shift
    printf -- '%s: %s: %s\n' "$prog_name" "$severity" "$*" >&2
  fi
}

err() {
  prog_msg 'Error' "$@"
}

warn() {
  prog_msg 'Warning' "$@"
}

dbg() {
  if [[ "$debug" -eq 1 ]]; then
    prog_msg 'Debug' "$@"
  fi
}

# prefer gsed (GNU sed) over the system's default sed
type gsed > /dev/null 2>&1 && SED='gsed' || SED='sed'
# prefer ggrep (GNU grep) over the system's default grep
type ggrep > /dev/null 2>&1 && GREP='ggrep' || GREP='grep'

cleanup() {
  rm -rf -- "$temp_dir" "$temp_infile"
}
trap 'cleanup' EXIT

equal_chars() {
  if { test -z "$1" || test "$1" -lt 1; }; then
    err 'function equal_chars() requires a positive number.'
    exit 1
  fi
  printf -- '% *s\n' "$1" ' ' | tr ' ' '='
}

fold_it_1() {
  # where to fold
  foldcol=$((maxcol - 1)) # for the inserted '\' char

  # ensure input file doesn't contain whitespace on the fold column
  if "$GREP" -q -- "^\(.\{$foldcol\}\)\{1,\} " "$infile"; then
    err "infile '$infile' has a space character occurring on the"\
        "folding column.  This file cannot be folded using the"\
        "'\\' strategy."
    return 1
  fi

  # center header text
  length=$((${#hdr_txt_1} + 2))
  left_sp=$(( (maxcol - length) / 2 ))
  right_sp=$((maxcol - length - left_sp))
  header=$(printf -- '%s %s %s' "$(equal_chars "$left_sp")" \
                     "$hdr_txt_1" "$(equal_chars "$right_sp")")

  # generate outfile
  printf -- '%s\n\n' "$header" > "$outfile"
  # shellcheck disable=SC1004
  "$SED" -- 's/\\$/\\\\\
  /' "$infile" | "$SED" 's/\(.\{'"$foldcol"'\}\)\(..\)/\1\\\
\2/;t M
    b
    :M
    P;D' >> "$outfile" \
  || return 1
  return 0
}

fold_it_2() {
  # where to fold
  foldcol=$((maxcol - 1)) # for the inserted '\' char

  # center header text
  length=$((${#hdr_txt_2} + 2))
  left_sp=$(( (maxcol - length) / 2))
  right_sp=$((maxcol - length - left_sp))
  header=$(printf -- '%s %s %s' "$(equal_chars "$left_sp")" \
                     "$hdr_txt_2" "$(equal_chars "$right_sp")")

  # generate outfile
  printf -- '%s\n\n' "$header" > "$outfile"
  # shellcheck disable=SC1004
  "$SED" -- '{
      H;$!d
    };x;s/^\n//;s/\\\(\n *\\\)/\\\\\
\\\1/g' "$infile" | \
  "$SED" 's/\(.\{'"$foldcol"'\}\)\(..\)/\1\\\
\\\2/;t M
    b
    :M
    P;D' >> "$outfile" \
  || return 1
  return 0
}

fold_it() {
  # ensure input file doesn't contain a tab
  if "$GREP" -q -- $'\t' "$infile"; then
    err "infile '$infile' contains a tab character, which is not"\
        "allowed."
    return 1
  fi

  # folding of input containing ASCII control or non-ASCII characters
  # may result in a wrong folding column and is not supported
  od -An -tx1 -- "$infile" | \
    "$GREP" -Eq '0[0-9]|0[BCEFbcef]|1[0-9A-Fa-f]|7[Ff]' \
    && warn "infile '$infile' contains ASCII control characters" \
            "(unsupported)."
  od -An -tx1 -- "$infile" | "$GREP" -q '[89A-Fa-f][0-9A-Fa-f]' \
    && warn "infile '$infile' contains non-ASCII characters" \
            "(unsupported)."

  # check if file needs folding
  testcol=$((maxcol + 1))
  if ! "$GREP" -q -- ".\{$testcol\}" "$infile"; then
    dbg "nothing to do; copying infile to outfile."
    cp -- "$infile" "$outfile"
    return 255
  fi

  if [[ "$strategy" -eq 1 ]]; then
    fold_it_1
    return $?
  fi
  if [[ "$strategy" -eq 2 ]]; then
    fold_it_2
    return $?
  fi
  quiet_sav="$quiet"
  quiet=1
  fold_it_1
  result=$?
  quiet="$quiet_sav"
  if [[ "$result" -ne 0 ]]; then
    dbg "Folding strategy '1' didn't succeed; trying strategy '2'..."
    fold_it_2
    return $?
  fi
  return 0
}

unfold_it_1() {
  temp_dir=$(mktemp -d)

  # output all but the first two lines (the header) to wip file
  awk -- "NR>2" "$infile" > "$temp_dir/wip"

  # unfold wip file
  "$SED" -- '{
      H;$!d
    };x;s/^\n//;s/\\\n *//g' "$temp_dir/wip" > "$outfile" \
  || return 1
  return 0
}

unfold_it_2() {
  temp_dir=$(mktemp -d)

  # output all but the first two lines (the header) to wip file
  awk -- "NR>2" "$infile" > "$temp_dir/wip"

  # unfold wip file
  "$SED" -- '{
      H;$!d
    };x;s/^\n//;s/\\\n *\\//g' "$temp_dir/wip" > "$outfile" \
  || return 1
  return 0
}

unfold_it() {
  # check if file needs unfolding
  line=$(head -n 1 -- "$infile")
  line2=$("$SED" -n -- '2p' "$infile")
  if result=$(printf -- '%s\n' "$line" | "$GREP" -F "$hdr_txt_1")
  then
    if [[ -n "$line2" ]]; then
      err "the second line in '$infile' is not empty."
      return 1
    fi
    unfold_it_1
    return $?
  fi
  if result=$(printf -- '%s\n' "$line" | "$GREP" -F "$hdr_txt_2")
  then
    if [[ -n "$line2" ]]; then
      err "the second line in '$infile' is not empty."
      return 1
    fi
    unfold_it_2
    return $?
  fi
  dbg "nothing to do; copying infile to outfile."
  cp -- "$infile" "$outfile"
  return 255
}

process_input() {
  while [[ "$1" != "" ]]; do
    if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
      print_usage
      exit 0
    elif [[ "$1" == "-V" ]] || [[ "$1" == "--version" ]]; then
      print_version
      exit 0
    elif [[ "$1" == "-d" ]]; then
      debug=1
    elif [[ "$1" == "-q" ]]; then
      quiet=1
    elif [[ "$1" == "-s" ]]; then
      if [[ "$#" -eq "1" ]]; then
        err "option '-s' needs an argument (use -h for help)."
        exit 1
      fi
      strategy="$2"
      shift
    elif [[ "$1" == "-c" ]]; then
      if [[ "$#" -eq "1" ]]; then
        err "option '-c' needs an argument (use -h for help)."
        exit 1
      fi
      col_gvn=1
      maxcol="$2"
      shift
    elif [[ "$1" == "-r" ]]; then
      reversed=1
    elif [[ "$1" == "-i" ]]; then
      if [[ "$#" -eq "1" ]]; then
        err "option '-i' needs an argument (use -h for help)."
        exit 1
      fi
      infile="$2"
      shift
    elif [[ "$1" == "-o" ]]; then
      if [[ "$#" -eq "1" ]]; then
        err "option '-o' needs an argument (use -h for help)."
        exit 1
      fi
      outfile="$2"
      shift
    else
      warn "ignoring unknown option '$1'."
    fi
    shift
  done

  dbg "$prog_name $prog_version using interpreter $BASH" \
      "version $BASH_VERSION on ${BASH_VERSINFO[5]}"
  dbg "Bash options: $BASHOPTS"
  dbg "sed binary: $(type "$SED")"
  dbg "grep binary: $(type "$GREP")"

  if [[ -z "$infile" ]]; then
    err "infile parameter missing (use -h for help)."
    exit 1
  fi

  if [[ -z "$outfile" ]]; then
    err "outfile parameter missing (use -h for help)."
    exit 1
  fi

  if [[ ! -e "$infile" ]]; then
    err "specified file '$infile' does not exist."
    exit 1
  elif [[ ! -r "$infile" ]]; then
    err "specified infile '$infile' cannot be read."
  elif [[ ! -f "$infile" ]]; then
    dbg "specified infile '$infile' is not a regular file."
    temp_infile=$(mktemp)
    dbg "writing infile to temporary file '$temp_infile'."
    cat -- "$infile" > "$temp_infile"
    infile=$temp_infile
  else
    dbg "specified infile '$infile' is a regular file."
  fi

  if [[ "$reversed" -eq 1 ]]; then
    if [[ "$col_gvn" -eq 1 ]]; then
      warn "'-c' option ignored when unfolding (option '-r')."
    fi
    if [[ "$strategy" -ne 0 ]]; then
      warn "'-s' option ignored when unfolding (option '-r')."
    fi
  fi

  if [[ "$strategy" -eq 0 ]] || [[ "$strategy" -eq 2 ]]; then
    min_supported=$((${#hdr_txt_2} + 8))
  else
    min_supported=$((${#hdr_txt_1} + 8))
  fi
  if [[ "$maxcol" -lt "$min_supported" ]]; then
    err "the folding column cannot be less than $min_supported."
    exit 1
  fi
  dbg "testing grep support for folding column value '$maxcol'..."
  # testcol == maxcol + 1
  echo a | "$GREP" -q "a\{1,$((maxcol+1))\}" || {
    err "folding column '$maxcol' is too big for grep."
    exit 1
  }
  dbg "testing sed support for folding column value '$maxcol'..."
  # foldcol == maxcol - 1
  echo a | "$SED" -n "s/a\{1,$((maxcol-1))\}//" || {
    err "folding column '$maxcol' is too big for '$SED'."
    exit 1
  }
}

main() {
  if [[ "$#" -eq "0" ]]; then
     print_usage
     exit 1
  fi

  process_input "$@"

  dbg "infile='$infile', outfile='$outfile'"
  dbg "strategy='$strategy', reversed='$reversed'," \
      "maxcol='$maxcol', col_gvn='$col_gvn'"

  [[ ! -s "$infile" ]] && warn "input file '$infile' is empty"

  if [[ "$reversed" -eq 0 ]]; then
    fold_it
    code=$?
  else
    unfold_it
    code=$?
  fi
  exit "$code"
}

main "$@"
