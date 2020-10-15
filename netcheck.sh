#!/usr/bin/env bash
### Created by Peter Forret ( pforret ) on 2020-10-15
script_version="0.0.0"  # if there is a VERSION.md in this script's folder, it will take priority for version number
readonly script_author="peter@forret.com"
readonly script_creation="2020-10-15"
readonly run_as_root=-1 # run_as_root: 0 = don't check anything / 1 = script MUST run as root / -1 = script MAY NOT run as root

list_options() {
echo -n "
#commented lines will be filtered
flag|h|help|show usage
flag|q|quiet|no output
flag|v|verbose|output more
flag|f|force|do not ask for confirmation (always yes)
flag|r|rx|check for tx/rx traffic too
option|d|domain|domain to check for|www.google.com
option|n|ns|nameserver to use as fallback|8.8.8.8
option|p|port|port to check for|80
option|t|tmp_dir|folder for temporary files|.tmp
option|l|log_dir|folder for log files|log
param|1|action|action to perform: check/...
" | grep -v '^#'
}

#####################################################################
## Put your main script here
#####################################################################

main() {
    log "Program: $script_basename $script_version"
    log "Updated: $prog_modified"
    log "Run as : $USER@$HOSTNAME"
    # add programs you need in your script here, like tar, wget, ffmpeg, rsync ...
    verify_programs awk basename cut date dirname find grep head mkdir sed stat tput uname wc
    prep_log_and_temp_dir

    problems_found=0
    fatal_problem=0

    action=$(lower_case "$action")
    case $action in
    check )
        # shellcheck disable=SC2154
        chapter "CHECK NETWORK CARDS" "is your machine connected via wifi or cable?"
        [[ $fatal_problem -eq 0 ]] && default_interface
        [[ $fatal_problem -eq 0 ]] && check_local

        chapter "CHECK NETWORK CONNECTIONS" "does your gateway respond?"
        [[ $fatal_problem -eq 0 ]] && check_allif

        chapter "CHECK DNS RESOLUTION" "can you reach the internet?"
        [[ $fatal_problem -eq 0 ]] && check_alldns

        chapter "CHECK HTTP TRAFFIC" "can you access the web?"
        [[ $fatal_problem -eq 0 ]] && check_conn
        
        chapter "PROBLEMS FOUND: $problems_found" ""
        ;;

    *)
        die "action [$action] not recognized"
    esac
}

#####################################################################
## Put your helper scripts here
#####################################################################

default_interface(){
  defaultif=$(netstat -nr | grep ^0.0.0.0 | awk '{print $8}' | head -1)
  if [ -z "$defaultif" ] ; then
    defaultif=none
    alert "WARN: This system does not have a default route"
    problems_found=$((problems_found + 1))
  elif [ $(netstat -nr | grep ^0.0.0.0 | wc -l) -gt 1 ] ; then
    alert "WARN: This system has more than one default route"
    problems_found=$((problems_found + 1))
  else 
    success "This system has a default route, interface <$defaultif>"
  fi
}

ping_host () {
  [[ -z "${1:-}" ]] && return 1
  host="$1"
  count=10
  [[ -n "${2:-}" ]] && count="$2"
  ping -q -c $count "$host" >/dev/null 2>&1 
  if [ "$?" -ne 0 ]; then
    log "WARN: Host <$host> does not answer to ICMP pings"
    return 1
  else
    log "Host <$host> answers to ICMP pings"
  fi
  return 0
}

check_router () {
  [[ -z "${1:-}" ]] && return 1
  router="$1"
  ping_host "$router" 3
  if [ "$?" -ne 0 ]; then
    alert "WARN: Router <$router> does not answer to ICMP pings"
    routerarp=`arp -n | grep "^$router" | grep -v incomplete`
    if [[ -z "$routerarp" ]] ; then
      alert "ERR: We cannot retrieve a MAC address for router $router"
      problems_found=$((problems_found + 1))
      return 1
    fi
    problems_found=$((problems_found + 1))
    return 1
  fi
  success "The router <$router> is reachable"
  return 0
}

check_local () {
  if [[ -z $(ifconfig | grep Link | grep lo) ]] ; then
    alert "ERR: There is no loopback interface in this system"
    problems_found=$(expr $problems_found + 1)
    return 1
  fi
  if ! ping_host 127.0.0.1 1 > /dev/null ; then
    alert "Cannot ping localhost (127.0.0.1), loopback is broken in this system"
    problems_found=$(expr $problems_found + 1)
    return 1
  fi
  if ! ping_host localhost 1 > /dev/null; then
    alert "check /etc/hosts and verify localhost points to 127.0.0.1"
    problems_found=$(expr $problems_found + 1)
    return 1
  fi
  success "Loopback interface is working properly"
  return 0
}

check_netroute () {
  ifname="$1"
  [[ -z "$ifname" ]] && return 1
  netstat -nr  | grep "${ifname}$" \
  | while read -r network gw netmask flags mss window irtt iface; do
    # For each gw that is not the default one, ping it
    if [[ "$gw" != "0.0.0.0" && "$gw" != "" ]] ; then
      log "check gateway $gw ..."
      if ! check_router $gw  ; then
        alert "ERR: The default route is not available since the default router <$gw> is unreachable"
      else
        out "Gateway $gw is reachable"
      fi
    fi
  done
}

check_if () {
  ifname=$1
  status=0
  [ -z "$ifname" ] && return 1
  # Find IP addresses for $ifname
  inetaddr=$(ip addr show $ifname| awk '/inet / {print $2}')
  if [[ -z "$inetaddr" ]] ; then
    alert "WARN: Interface <$ifname>: no IP address assigned"
    problems_found=$(expr $problems_found + 1)
    return 1
  fi
  echo $inetaddr | while read -r ipaddr; do
    success "Interface <$ifname>: IP address(es) <$ipaddr>"
  done

  ip route show \
  | grep "$ifname" \
  | awk '$1 == "default" {print $3} $2 == "default" {print $4}' \
  | while read -r gateway ; do
      success "Gateway for <$ifname>: <$gateway>"
    done
  
  (( $rx )) && (
    txpkts=`ifconfig $ifname | awk '/TX packets/ { print $2 }' |sed 's/.*://'`
    rxpkts=`ifconfig $ifname | awk '/RX packets/ { print $2 }' |sed 's/.*://'`
    txerrors=`ifconfig $ifname | awk '/TX packets/ { print $3 }' |sed 's/.*://'`
    rxerrors=`ifconfig $ifname | awk '/RX packets/ { print $3 }' |sed 's/.*://'`

    if [[ "$txpkts" -eq 0 ]] && [[ "$rxpkts" -eq 0 ]] ; then
      alert "ERR: Interface <$ifname>: has not tx or rx any packets. Link down?"
      problems_found=$(( $problems_found + 1))
      return 1
    elif [[ "$txpkts" -eq 0 ]] ; then
      alert "WARN: Interface <$ifname>: has not transmitted any packets."
    elif [ "$rxpkts" -eq 0 ] ; then
      alert "WARN: Interface <$ifname>: has not received any packets."
    else
      log "Interface <$ifname>: has tx and rx packets."
    fi

    if [ "$txerrors" -ne 0 ]; then
      echo "WARN: Interface <$ifname>: has tx errors."
      problems_found=$(( $problems_found + 1))
      return 1
    fi
    if [ "$rxerrors" -ne 0 ]; then
      echo "WARN: Interface <$ifname>: has rx errors."
      problems_found=$(( $problems_found + 1))
      return 1
    fi
    )
  return 0
}

check_allif () {
  status=0
  iffound=0
  ifok=0
  ifnames=$(ip link show | awk -F: '$1 > 0 { gsub(/ /,"",$2); print $2}')
  for ifname in $ifnames ; do
    #ifname=$(echo $ifname | sed -e 's/:$//')
    [[ $ifname == lo ]] && continue
    iffound=$(( iffound +1 ))
    if [ -z "$(ifconfig $ifname | grep UP)" ] ; then
      if  [ "$ifname" = "$defaultif" ] ; then
        alert "ERR: Interface <$ifname>: default route is down!"
        status=1
      elif  [ "$ifname" = "lo"  ] ; then
        alert "ERR: Interface <$ifname>: is down, this might cause issues with local applications"
      else
        log "WARN: Interface <$ifname>: is down"
      fi
    else
    # Check network routes associated with this interface
      log "Interface <$ifname>: is up!"
      if check_if $ifname ; then
        if check_netroute $ifname ; then
          ifok=$(( ifok +1 ))
        fi
      fi
    fi
  done
  log "Interface: $ifok of $iffound interfaces are OK"
  if [[ $ifok -lt 1 ]] ;  then
    fatal_problem=1
    problems_found=$(( problems_found + 1))
  fi
  return $status
}

check_ns(){
  nameserver=$1
  [[ -z "$nameserver" ]] && return 1
  lookuplast=`host -W 5 $domain $nameserver 2>&1 | tail -1`
  log "$domain@$nameserver: '$lookuplast'"

  if [[ -n $(echo $lookuplast | grep NXDOMAIN) ]] ; then
    # example: host www.google.comp 8.8.8.8
    log "ERR: DNS <$nameserver>: domain <$domain> could not be resolved"
    problems_found=$(expr $problems_found + 1)
    return 1
  fi

  if [[ -n $(echo $lookuplast | grep "timed out") ]] ; then
    # example: host www.google.com 8.8.8.7
    log "ERR: DNS <$nameserver>: NS server does not respond"
    problems_found=$(expr $problems_found + 1)
    return 1
  fi
  ipaddresses=$(host -W 5 $domain $nameserver | grep has | awk '/address/ {print $NF}')
  for ipaddress in $ipaddresses ; do
    success "DNS <$nameserver>: resolves <$domain> to <$ipaddress>"
  done
}

check_alldns(){
  status=1
  nsfound=0
  nsok=0
  nameservers=$( cat /etc/resolv.conf | grep nameserver | awk '{print $2}')
  if ! check_ns $ns ; then
    alert "ERR: DNS <$ns>: cannot resolve <$domain>"
    problems_found=$(expr $problems_found + 1)
    return 1    
  fi
  for nameserver in $nameservers ;  do
    nsfound=$(( $nsfound + 1 ))
    log "DNS <$nameserver>: used as nameserver"
    if ping_host $nameserver 5 ; then
      if check_ns $nameserver ; then
        nsok=$(( $nsok +1 ))
      else
        problems_found=$(expr $problems_found + 1)
        status=$?
      fi
    fi
  done
  log "DNS: $nsok of $nsfound nameservers are OK"
  if [[ $nsok -lt 1 ]] ;  then
    fatal_problem=1
    problems_found=$(expr $problems_found + 1)
  fi

}

check_conn () {
# Checks network connectivity
  if ! ping_host $domain ; then
    alert "WARN: Host <$domain>: cannot be reached by ICMP ping"
    problems_found=$(expr $problems_found + 1)
  else
    success "Host <$domain>: can be reached by ICMP ping"
  fi
# Check web access, using nc
  httpversion=$(echo -e "HEAD / HTTP/1.0\n\n" | nc $domain $port 2>/dev/null  | grep HTTP)
  if [ $? -ne 0 ] ; then
    alert "WARN: Host <$domain:$port>: no response"
    problems_found=$(expr $problems_found + 1)
  else
    success "Host <$domain:$port>: web server responds!"
  fi
}

chapter () {
  out "\n## $1"
  if [[ "$2" != "" ]] ; then
    out "-- $2"
  fi

}

#####################################################################
################### DO NOT MODIFY BELOW THIS LINE ###################

# set strict mode -  via http://redsymbol.net/articles/unofficial-bash-strict-mode/
# removed -e because it made basic [[ testing ]] difficult
set -uo pipefail
IFS=$'\n\t'
# shellcheck disable=SC2120
hash(){
  length=${1:-6}
  # shellcheck disable=SC2230
  if [[ -n $(which md5sum) ]] ; then
    # regular linux
    md5sum | cut -c1-"$length"
  else
    # macos
    md5 | cut -c1-"$length"
  fi 
}
#TIP: use «hash» to create short unique values of fixed length based on longer inputs
#TIP:> url_contents="$domain.$(echo $url | hash 8).html"


prog_modified="??"
os_name=$(uname -s)
[[ "$os_name" = "Linux" ]]  && prog_modified=$(stat -c %y    "${BASH_SOURCE[0]}" 2>/dev/null | cut -c1-16) # generic linux
[[ "$os_name" = "Darwin" ]] && prog_modified=$(stat -f "%Sm" "${BASH_SOURCE[0]}" 2>/dev/null) # for MacOS

force=0
help=0

## ----------- TERMINAL OUTPUT STUFF

[[ -t 1 ]] && piped=0 || piped=1        # detect if out put is piped
verbose=0
#to enable verbose even before option parsing
[[ $# -gt 0 ]] && [[ $1 == "-v" ]] && verbose=1
quiet=0
#to enable quiet even before option parsing
[[ $# -gt 0 ]] && [[ $1 == "-q" ]] && quiet=1

[[ $(echo -e '\xe2\x82\xac') == '€' ]] && unicode=1 || unicode=0 # detect if unicode is supported


if [[ $piped -eq 0 ]] ; then
  col_reset="\033[0m" ; col_red="\033[1;31m" ; col_grn="\033[1;32m" ; col_ylw="\033[1;33m"
else
  col_reset="" ; col_red="" ; col_grn="" ; col_ylw=""
fi

if [[ $unicode -gt 0 ]] ; then
  char_succ="✔" ; char_fail="✖" ; char_alrt="➨" ; char_wait="…"
else
  char_succ="OK " ; char_fail="!! " ; char_alrt="?? " ; char_wait="..."
fi

readonly nbcols=$(tput cols || echo 80)
#readonly nbrows=$(tput lines)
readonly wprogress=$((nbcols - 5))

out() { ((quiet)) || printf '%b\n' "$*";  }
#TIP: use «out» to show any kind of output, except when option --quiet is specified
#TIP:> out "User is [$USER]"

progress() {
  ((quiet)) || (
    ((piped)) && out "$*" || printf "... %-${wprogress}b\r" "$*                                             ";
  )
}
#TIP: use «progress» to show one line of progress that will be overwritten by the next output
#TIP:> progress "Now generating file $nb of $total ..."

die()     { tput bel; out "${col_red}${char_fail} $script_basename${col_reset}: $*" >&2; safe_exit; }
fail()    { tput bel; out "${col_red}${char_fail} $script_basename${col_reset}: $*" >&2; safe_exit; }
#TIP: use «die» to show error message and exit program
#TIP:> if [[ ! -f $output ]] ; then ; die "could not create output" ; fi

alert()   { out "${col_red}${char_alrt}${col_reset}: $*" >&2 ; }                       # print error and continue
#TIP: use «alert» to show alert/warning message but continue
#TIP:> if [[ ! -f $output ]] ; then ; alert "could not create output" ; fi

success() { out "${col_grn}${char_succ}${col_reset}  $*" ; }
#TIP: use «success» to show success message but continue
#TIP:> if [[ -f $output ]] ; then ; success "output was created!" ; fi

announce(){ out "${col_grn}${char_wait}${col_reset}  $*"; sleep 1 ; }
#TIP: use «announce» to show the start of a task
#TIP:> announce "now generating the reports"

log()   { ((verbose)) && out "${col_ylw}# $* ${col_reset}" >&2 ; }
#TIP: use «log» to show information that will only be visible when -v is specified
#TIP:> log "input file: [$inputname] - [$inputsize] MB"

lower_case()   { echo "$*" | awk '{print tolower($0)}' ; }
upper_case()   { echo "$*" | awk '{print toupper($0)}' ; }
#TIP: use «lower_case» and «upper_case» to convert to upper/lower case
#TIP:> param=$(lower_case $param)

confirm() { is_set $force && return 0; read -r -p "$1 [y/N] " -n 1; echo " "; [[ $REPLY =~ ^[Yy]$ ]];}
#TIP: use «confirm» for interactive confirmation before doing something
#TIP:> if ! confirm "Delete file"; then ; echo "skip deletion" ;   fi

ask() {
  # $1 = variable name
  # $2 = question
  # $3 = default value
  # not using read -i because that doesn't work on MacOS
  local ANSWER
  read -r -p "$2 ($3) > " ANSWER
  if [[ -z "$ANSWER" ]] ; then
    eval "$1=\"$3\""
  else
    eval "$1=\"$ANSWER\""
  fi
}
#TIP: use «ask» for interactive setting of variables
#TIP:> ask NAME "What is your name" "Peter"

error_prefix="${col_red}>${col_reset}"
trap "die \"ERROR \$? after \$SECONDS seconds \n\
\${error_prefix} last command : '\$BASH_COMMAND' \" \
\$(< \$script_install_path awk -v lineno=\$LINENO \
'NR == lineno {print \"\${error_prefix} from line \" lineno \" : \" \$0}')" INT TERM EXIT
# cf https://askubuntu.com/questions/513932/what-is-the-bash-command-variable-good-for
# trap 'echo ‘$BASH_COMMAND’ failed with error code $?' ERR
safe_exit() { 
  [[ -n "${tmp_file:-}" ]] && [[ -f "$tmp_file" ]] && rm "$tmp_file"
  trap - INT TERM EXIT
  log "$script_basename finished after $SECONDS seconds"
  exit 0
}

is_set()       { [[ "$1" -gt 0 ]]; }
is_empty()     { [[ -z "$1" ]] ; }
is_not_empty() { [[ -n "$1" ]] ; }
#TIP: use «is_empty» and «is_not_empty» to test for variables
#TIP:> if is_empty "$email" ; then ; echo "Need Email!" ; fi

is_file() { [[ -f "$1" ]] ; }
is_dir()  { [[ -d "$1" ]] ; }
#TIP: use «is_file» and «is_dir» to test for files or folders
#TIP:> if is_file "/etc/hosts" ; then ; cat "/etc/hosts" ; fi

show_usage() {
  out "Program: ${col_grn}$script_basename $script_version${col_reset} by ${col_ylw}$script_author${col_reset}"
  out "Updated: ${col_grn}$prog_modified${col_reset}"

  echo -n "Usage: $script_basename"
   list_options \
  | awk '
  BEGIN { FS="|"; OFS=" "; oneline="" ; fulltext="Flags, options and parameters:"}
  $1 ~ /flag/  {
    fulltext = fulltext sprintf("\n    -%1s|--%-10s: [flag] %s [default: off]",$2,$3,$4) ;
    oneline  = oneline " [-" $2 "]"
    }
  $1 ~ /option/  {
    fulltext = fulltext sprintf("\n    -%1s|--%s <%s>: [optn] %s",$2,$3,"val",$4) ;
    if($5!=""){fulltext = fulltext "  [default: " $5 "]"; }
    oneline  = oneline " [-" $2 " <" $3 ">]"
    }
  $1 ~ /secret/  {
    fulltext = fulltext sprintf("\n    -%1s|--%s <%s>: [secr] %s",$2,$3,"val",$4) ;
      oneline  = oneline " [-" $2 " <" $3 ">]"
    }
  $1 ~ /param/ {
    if($2 == "1"){
          fulltext = fulltext sprintf("\n    %-10s: [parameter] %s","<"$3">",$4);
          oneline  = oneline " <" $3 ">"
     } else {
          fulltext = fulltext sprintf("\n    %-10s: [parameters] %s (1 or more)","<"$3">",$4);
          oneline  = oneline " <" $3 " …>"
     }
    }
    END {print oneline; print fulltext}
  '
}

show_tips(){
  < "${BASH_SOURCE[0]}" grep -v "\$0" \
  | awk "
  /TIP: / {\$1=\"\"; gsub(/«/,\"$col_grn\"); gsub(/»/,\"$col_reset\"); print \"*\" \$0}
  /TIP:> / {\$1=\"\"; print \" $col_ylw\" \$0 \"$col_reset\"}
  "
}

init_options() {
	local init_command
    init_command=$(list_options \
    | awk '
    BEGIN { FS="|"; OFS=" ";}
    $1 ~ /flag/   && $5 == "" {print $3 "=0; "}
    $1 ~ /flag/   && $5 != "" {print $3 "=\"" $5 "\"; "}
    $1 ~ /option/ && $5 == "" {print $3 "=\"\"; "}
    $1 ~ /option/ && $5 != "" {print $3 "=\"" $5 "\"; "}
    ')
    if [[ -n "$init_command" ]] ; then
        #log "init_options: $(echo "$init_command" | wc -l) options/flags initialised"
        eval "$init_command"
   fi
}

verify_programs(){
  os_name=$(uname -s)
  os_version=$(uname -v)
  log "Running: on $os_name ($os_version)"
  list_programs=$(echo "$*" | sort -u |  tr "\n" " ")
  log "Verify : $list_programs"
  for prog in "$@" ; do
    # shellcheck disable=SC2230
    if [[ -z $(which "$prog") ]] ; then
      die "$script_basename needs [$prog] but this program cannot be found on this [$os_name] machine"
    fi
  done
}

folder_prep(){
  if [[ -n "$1" ]] ; then
      local folder="$1"
      local max_days=${2:-365}
      if [[ ! -d "$folder" ]] ; then
          log "Create folder : [$folder]"
          mkdir "$folder"
      else
          log "Cleanup folder: [$folder] - delete files older than $max_days day(s)"
          find "$folder" -mtime "+$max_days" -type f -exec rm {} \;
      fi
  fi
}
#TIP: use «folder_prep» to create a folder if needed and otherwise clean up old files
#TIP:> folder_prep "$log_dir" 7 # delete all files olders than 7 days

expects_single_params(){
  list_options | grep 'param|1|' > /dev/null
  }
expects_multi_param(){
  list_options | grep 'param|n|' > /dev/null
  }

parse_options() {
    if [[ $# -eq 0 ]] ; then
       show_usage >&2 ; safe_exit
    fi

    ## first process all the -x --xxxx flags and options
    #set -x
    while true; do
      # flag <flag> is savec as $flag = 0/1
      # option <option> is saved as $option
      if [[ $# -eq 0 ]] ; then
        ## all parameters processed
        break
      fi
      if [[ ! $1 = -?* ]] ; then
        ## all flags/options processed
        break
      fi
	  local save_option
      save_option=$(list_options \
        | awk -v opt="$1" '
        BEGIN { FS="|"; OFS=" ";}
        $1 ~ /flag/   &&  "-"$2 == opt {print $3"=1"}
        $1 ~ /flag/   && "--"$3 == opt {print $3"=1"}
        $1 ~ /option/ &&  "-"$2 == opt {print $3"=$2; shift"}
        $1 ~ /option/ && "--"$3 == opt {print $3"=$2; shift"}
        $1 ~ /secret/ &&  "-"$2 == opt {print $3"=$2; shift"}
        $1 ~ /secret/ && "--"$3 == opt {print $3"=$2; shift"}
        ')
        if [[ -n "$save_option" ]] ; then
          if echo "$save_option" | grep shift >> /dev/null ; then
            local save_var
            save_var=$(echo "$save_option" | cut -d= -f1)
            log "Found  : ${save_var}=$2"
          else
            log "Found  : $save_option"
          fi
          eval "$save_option"
        else
            die "cannot interpret option [$1]"
        fi
        shift
    done

    ((help)) && (
      echo "### USAGE"
      show_usage
      echo ""
      echo "### SCRIPT AUTHORING TIPS"
      show_tips
      safe_exit
    )

    ## then run through the given parameters
  if expects_single_params ; then
    single_params=$(list_options | grep 'param|1|' | cut -d'|' -f3)
    list_singles=$(echo "$single_params" | xargs)
    single_count=$(echo "$single_params" | wc -w)
    log "Expect : $single_count single parameter(s): $list_singles"
    [[ $# -eq 0 ]] && die "need the parameter(s) [$list_singles]"

    for param in $single_params ; do
      [[ $# -eq 0 ]] && die "need parameter [$param]"
      [[ -z "$1" ]]  && die "need parameter [$param]"
      log "Found  : $param=$1"
      eval "$param=\"$1\""
      shift
    done
  else 
    log "No single params to process"
    single_params=""
    single_count=0
  fi

  if expects_multi_param ; then
    #log "Process: multi param"
    multi_count=$(list_options | grep -c 'param|n|')
    multi_param=$(list_options | grep 'param|n|' | cut -d'|' -f3)
    log "Expect : $multi_count multi parameter: $multi_param"
    (( multi_count > 1 )) && die "cannot have >1 'multi' parameter: [$multi_param]"
    (( multi_count > 0 )) && [[ $# -eq 0 ]] && die "need the (multi) parameter [$multi_param]"
    # save the rest of the params in the multi param
    if [[ -n "$*" ]] ; then
      log "Found  : $multi_param=$*"
      eval "$multi_param=( $* )"
    fi
  else 
    multi_count=0
    multi_param=""
    [[ $# -gt 0 ]] && die "cannot interpret extra parameters"
  fi
}

lookup_script_data(){
  readonly script_prefix=$(basename "${BASH_SOURCE[0]}" .sh)
  readonly script_basename=$(basename "${BASH_SOURCE[0]}")
  readonly execution_day=$(date "+%Y-%m-%d")
  readonly execution_year=$(date "+%Y")

   if [[ -z $(dirname "${BASH_SOURCE[0]}") ]]; then
    # script called without path ; must be in $PATH somewhere
    # shellcheck disable=SC2230
    script_install_path=$(which "${BASH_SOURCE[0]}")
    if [[ -n $(readlink "$script_install_path") ]] ; then
      # when script was installed with e.g. basher
      script_install_path=$(readlink "$script_install_path") 
    fi
    script_install_folder=$(dirname "$script_install_path")
  else
    # script called with relative/absolute path
    script_install_folder=$(dirname "${BASH_SOURCE[0]}")
    # resolve to absolute path
    script_install_folder=$(cd "$script_install_folder" && pwd)
    if [[ -n "$script_install_folder" ]] ; then
      script_install_path="$script_install_folder/$script_basename"
    else
      script_install_path="${BASH_SOURCE[0]}"
      script_install_folder=$(dirname "${BASH_SOURCE[0]}")
    fi
    if [[ -n $(readlink "$script_install_path") ]] ; then
      # when script was installed with e.g. basher
      script_install_path=$(readlink "$script_install_path") 
      script_install_folder=$(dirname "$script_install_path")
    fi
  fi
  log "Executable: [$script_install_path]"
  log "In folder : [$script_install_folder]"

  [[ -f "$script_install_folder/VERSION.md" ]] && script_version=$(cat "$script_install_folder/VERSION.md")
  if git status >/dev/null; then
    readonly in_git_repo=1
  else
    readonly in_git_repo=0
  fi
}

prep_log_and_temp_dir(){
  tmp_file=""
  log_file=""
  # shellcheck disable=SC2154
  if is_not_empty "$tmp_dir" ; then
    folder_prep "$tmp_dir" 1
    tmp_file=$(mktemp "$tmp_dir/$execution_day.XXXXXX")
    log "tmp_file: $tmp_file"
    # you can use this teporary file in your program
    # it will be deleted automatically if the program ends without problems
  fi
  # shellcheck disable=SC2154
  if [[ -n "$log_dir" ]] ; then
    folder_prep "$log_dir" 7
    log_file=$log_dir/$script_prefix.$execution_day.log
    log "log_file: $log_file"
    echo "$(date '+%H:%M:%S') | [$script_basename] $script_version started" >> "$log_file"
  fi
}

import_env_if_any(){
  #TIP: use «.env» file in script folder / current folder to set secrets or common config settings
  #TIP:> AWS_SECRET_ACCESS_KEY="..."

  if [[ -f "$script_install_folder/.env" ]] ; then
    log "Read config from [$script_install_folder/.env]"
    # shellcheck disable=SC1090
    source "$script_install_folder/.env"
  fi
  if [[ -f "./.env" ]] ; then
    log "Read config from [./.env]"
    # shellcheck disable=SC1090
    source "./.env"
  fi
}

[[ $run_as_root == 1  ]] && [[ $UID -ne 0 ]] && die "user is $USER, MUST be root to run [$script_basename]"
[[ $run_as_root == -1 ]] && [[ $UID -eq 0 ]] && die "user is $USER, CANNOT be root to run [$script_basename]"

lookup_script_data

# set default values for flags & options
init_options

# overwrite with .env if any
import_env_if_any

# overwrite with specified options if any
parse_options "$@"

# run main program
main

# exit and clean up
safe_exit
