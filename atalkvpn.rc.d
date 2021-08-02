#!/bin/sh
#
# PROVIDE: atalktun
# REQUIRE: atalkd
#

$_rc_subr_loaded . /etc/rc.subr

name="atalktun"
rcvar=$name
command="/usr/pkg/bin/atalkvpn"
pidfile="/var/run/${name}.pid"

load_rc_config $name
run_rc_command "$1"

