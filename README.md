![GH Language](https://img.shields.io/github/languages/top/pforret/netcheck)
![GH stars](https://img.shields.io/github/stars/pforret/netcheck)
![GH tag](https://img.shields.io/github/v/tag/pforret/netcheck)
![GH License](https://img.shields.io/github/license/pforret/netcheck)
[![basher install](https://img.shields.io/badge/basher-install-white?logo=gnu-bash&style=flat)](https://basher.gitparade.com/package/)

# NetCheck

test network config for problems

## Installation

with [basher](https://github.com/basherpm/basher)

	$ basher install pforret/netcheck

or with `git`

	$ git clone https://github.com/pforret/netcheck.git
	$ cd testnetwork

## Usage

	Program: netcheck 1.0.0 by peter@forret.com
	Updated: 2020-10-15 02:00
	Usage: netcheck [-h] [-q] [-v] [-f] [-r] [-d <domain>] [-n <ns>] [-p <port>] [-t <tmp_dir>] [-l <log_dir>] <action>
	Flags, options and parameters:
	    -h|--help      : [flag] show usage [default: off]
	    -q|--quiet     : [flag] no output [default: off]
	    -v|--verbose   : [flag] output more [default: off]
	    -f|--force     : [flag] do not ask for confirmation (always yes) [default: off]
	    -r|--rx        : [flag] check for tx/rx traffic too [default: off]
	    -d|--domain <val>: [optn] domain to check for  [default: www.google.com]
	    -n|--ns <val>: [optn] nameserver to use as fallback  [default: 8.8.8.8]
	    -p|--port <val>: [optn] port to check for  [default: 80]
	    -t|--tmp_dir <val>: [optn] folder for temporary files  [default: .tmp]
	    -l|--log_dir <val>: [optn] folder for log files  [default: log]
	    <action>  : [parameter] action to perform: check/...

## Acknowledgements

* script created with [bashew](https://github.com/pforret/bashew)

&copy; 2020 Peter Forret
