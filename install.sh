#!/usr/bin/env bash
#
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
#
PATH=$PATH:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin
lmd_version="2.0.1"
inspath=/usr/local/maldetect
logf=/var/log/maldet/event_log

# Source shared packaging library
PKG_BACKUP_SYMLINK="maldetect.last"
PKG_BACKUP_PRUNE_DAYS="30"
# shellcheck disable=SC1091
source files/internals/pkg_lib.sh

# ClamAV integration (LMD-specific)

clamav_linksigs() {
	local cpath="$1"
	if [ -d "$cpath" ]; then
		command rm -f "$cpath"/rfxn.{hdb,ndb,yara,hsb} 2>/dev/null  # safe: ClamAV path may not have LMD sigs
		command cp -f "$inspath/sigs/rfxn.ndb" "$inspath/sigs/rfxn.hdb" "$inspath/sigs/rfxn.yara" "$cpath/" 2>/dev/null  # safe: ClamAV path may not exist
		[ -f "$inspath/sigs/rfxn.hsb" ] && [ -s "$inspath/sigs/rfxn.hsb" ] && \
			command cp -f "$inspath/sigs/rfxn.hsb" "$cpath"/ 2>/dev/null  # safe: ClamAV path may not exist
		command rm -f "$cpath"/lmd.user.* 2>/dev/null  # safe: user sigs may not exist
		[ -s "$inspath/sigs/lmd.user.ndb" ] && command cp -f "$inspath/sigs/lmd.user.ndb" "$cpath"/ 2>/dev/null  # safe: ClamAV path may not exist
		[ -s "$inspath/sigs/lmd.user.hdb" ] && command cp -f "$inspath/sigs/lmd.user.hdb" "$cpath"/ 2>/dev/null  # safe: ClamAV path may not exist
		[ -s "$inspath/sigs/lmd.user.hsb" ] && command cp -f "$inspath/sigs/lmd.user.hsb" "$cpath"/ 2>/dev/null  # safe: ClamAV path may not exist
	fi
}

clamav_paths="/usr/local/cpanel/3rdparty/share/clamav/ /var/lib/clamav/ /var/clamav/ /usr/share/clamav/ /usr/local/share/clamav"

# Core file installation (silent — no user output)

_install_core() {
	pkg_copy_tree "files" "$inspath"
	chmod 755 "$inspath"
	chmod 755 "$inspath/maldet"
	chmod 640 "$inspath/conf.maldet"
	test -f "$inspath/conf.maldet.hookscan" && chmod 640 "$inspath/conf.maldet.hookscan"
	test -f "$inspath/conf.maldet.hookscan.default" && chmod 640 "$inspath/conf.maldet.hookscan.default"
	pkg_create_dirs 750 "$inspath/clean" "$inspath/pub" "$inspath/quarantine" \
		"$inspath/sess" "$inspath/sigs" "$inspath/tmp"
	chmod 750 "$inspath/logs" "$inspath/internals/tlog" "$inspath/internals/alert" 2>/dev/null
	chmod 750 "$inspath/internals/tlog_lib.sh" "$inspath/internals/alert_lib.sh" \
		"$inspath/internals/elog_lib.sh" "$inspath/internals/pkg_lib.sh" 2>/dev/null
	# Sub-library permissions (decomposed from functions monolith)
	chmod 750 "$inspath/internals/lmd.lib.sh"
	# shellcheck disable=SC2086
	chmod 750 "$inspath/internals"/lmd_*.sh 2>/dev/null
	# shellcheck disable=SC2086
	chmod 640 "$inspath/internals/alert/"* 2>/dev/null
	# tlog: replace default BASERUN for cursor storage security
	sed -i "s|BASERUN=\"\${BASERUN:-/tmp}\"|BASERUN=\"\${BASERUN:-$inspath/tmp}\"|" "$inspath/internals/tlog"
	pkg_symlink "$inspath/maldet" /usr/local/sbin/maldet
	pkg_symlink "$inspath/maldet" /usr/local/sbin/lmd
	command cp -f CHANGELOG COPYING.GPL README "$inspath/"
	# Man page: compress in-place at install path, then symlink to system dir
	mkdir -p /usr/local/share/man/man1/
	gzip -9 "$inspath/maldet.1"
	pkg_symlink "$inspath/maldet.1.gz" /usr/local/share/man/man1/maldet.1.gz
	# Create empty custom sig files if absent (upgrade path: prior versions lack them)
	[ -f "$inspath/sigs/custom.sha256.dat" ] || touch "$inspath/sigs/custom.sha256.dat"
	[ -f "$inspath/sigs/custom.csig.dat" ] || touch "$inspath/sigs/custom.csig.dat"
	for lp in $clamav_paths; do
		clamav_linksigs "$lp"
	done
	killall -SIGUSR2 clamd 2>/dev/null  # safe: signal ClamAV to reload sigs
}

_read_conf_value() {
	# Read a single variable value from conf.maldet.
	# Handles both quoted (var="val") and unquoted (var=val) formats.
	local _var="$1" _default="${2:-}"
	local _val="$_default"
	if [ -f "$inspath/conf.maldet" ]; then
		_val=$(grep -m1 "^${_var}=" "$inspath/conf.maldet" \
			| command sed "s/^${_var}="'"\{0,1\}\([^"]*\)"\{0,1\}/\1/' 2>/dev/null)
		_val="${_val:-$_default}"
	fi
	echo "$_val"
}

# FHS log migration

_migrate_logs() {
	# FHS log migration: /var/log/maldet/ is the authoritative log location.
	# $inspath/logs becomes a symlink for backward compat.
	# Must run AFTER _install_core() — pkg_copy_tree may overwrite a prior symlink
	# with a real directory from the source tree.
	command mkdir -p /var/log/maldet
	command chmod 750 /var/log/maldet

	if [ -d "$inspath/logs" ] && [ ! -L "$inspath/logs" ]; then
		# Real directory — migrate contents then replace with symlink
		command cp -a "$inspath/logs/"* /var/log/maldet/ 2>/dev/null  # safe: dir may be empty on fresh install
		command rm -rf "$inspath/logs"
		command ln -sf /var/log/maldet "$inspath/logs"
	elif [ -L "$inspath/logs" ]; then
		# Already a symlink — verify target, re-create if wrong
		local _target
		_target=$(readlink "$inspath/logs")
		if [ "$_target" != "/var/log/maldet" ]; then
			command rm -f "$inspath/logs"
			command ln -sf /var/log/maldet "$inspath/logs"
		fi
	else
		# Does not exist — create symlink
		command ln -sf /var/log/maldet "$inspath/logs"
	fi
}

# Cron & service installation

_install_cron_service() {
	pkg_cron_install cron.daily /etc/cron.daily/maldet
	pkg_cron_install cron.watchdog /etc/cron.weekly/maldet-watchdog
	pkg_cron_install cron.d.pub /etc/cron.d/maldet_pub

	# Independent sig update cron (sigup_interval, default 6h)
	# Source installed conf.maldet to read sigup_interval — conf is already
	# copied by _install_core() which runs before _install_cron_service().
	# On upgrade, user's custom value is not yet imported (that happens in
	# importconf), so the default 6 is used. User changes to
	# sigup_interval take effect on next install.sh run.
	local _sigup_interval
	_sigup_interval=$(_read_conf_value "sigup_interval" "6")
	if [ "$_sigup_interval" != "0" ] && [ "$_sigup_interval" -gt 0 ] 2>/dev/null; then
		pkg_cron_install cron.d.sigup /etc/cron.d/maldet-sigup
		# Replace default interval with configured value
		if [ "$_sigup_interval" != "6" ]; then
			command sed -i "s|\\*/6|\\*/$_sigup_interval|g" /etc/cron.d/maldet-sigup
		fi
	else
		# sigup_interval=0: remove cron file if present (upgrade path)
		command rm -f /etc/cron.d/maldet-sigup 2>/dev/null
	fi

	if [ "$(uname -s)" != "FreeBSD" ]; then
		pkg_detect_os
		_init_system=$(cat /proc/1/comm 2>/dev/null)
		if test "$_init_system" == "systemd"; then
			pkg_service_install maldet ./files/service/maldet.service
			systemctl enable maldet.service 2>/dev/null  # safe: idempotent
		else
			pkg_service_install maldet ./files/service/maldet.sh
			if [ "$_PKG_OS_FAMILY" = "rhel" ] && command -v chkconfig >/dev/null 2>&1; then
				chkconfig --level 2345 maldet on
			fi
		fi
		# Read old default_monitor_mode for migration (applied after sysconfig install)
		_old_dmm=""
		if [ -n "${bkpath:-}" ] && [ -f "$bkpath/conf.maldet" ]; then
			_old_dmm=$(grep '^default_monitor_mode=' "$bkpath/conf.maldet" 2>/dev/null | tail -1 | sed 's/^default_monitor_mode=//' | tr -d '"')
		fi
		# Install sysconfig/default override file
		if [ "$_PKG_OS_FAMILY" = "rhel" ]; then
			if [ ! -f "/etc/sysconfig/maldet" ]; then
				command cp -f ./files/service/maldet.sysconfig /etc/sysconfig/maldet
			fi
		elif [ "$_PKG_OS_FAMILY" = "debian" ]; then
			if [ ! -f "/etc/default/maldet" ]; then
				command cp -f ./files/service/maldet.sysconfig /etc/default/maldet
			fi
			if [ "$_init_system" != "systemd" ]; then
				update-rc.d -f maldet remove
				update-rc.d maldet defaults 70 30
			fi
		elif [ "$_PKG_OS_FAMILY" = "gentoo" ]; then
			if [ "$_init_system" != "systemd" ]; then
				rc-update add maldet default
			fi
		elif [ "$_PKG_OS_FAMILY" = "slackware" ]; then
			if [ "$_init_system" != "systemd" ]; then
				# Slackware uses /etc/rc.d/rc.NAME; executable scripts are auto-started by rc.M
				ln -sf /etc/init.d/maldet /etc/rc.d/rc.maldet
				chmod +x /etc/rc.d/rc.maldet 2>/dev/null  # safe: symlink may point to newly installed init script
			fi
		else
			if [ ! -f "/etc/sysconfig/maldet" ]; then
				command cp -f ./files/service/maldet.sysconfig /etc/sysconfig/maldet 2>/dev/null  # safe: dir may not exist
			fi
		fi
		# Apply default_monitor_mode migration now that sysconfig file is guaranteed to exist
		if [ -n "${_old_dmm:-}" ] && [ "$_old_dmm" != "users" ]; then
			for _scf in /etc/sysconfig/maldet /etc/default/maldet; do
				if [ -f "$_scf" ]; then
					if grep -q '^MONITOR_MODE=' "$_scf"; then
						sed -i "s|^MONITOR_MODE=.*|MONITOR_MODE=\"$_old_dmm\"|" "$_scf"
					else
						echo "MONITOR_MODE=\"$_old_dmm\"" >> "$_scf"
					fi
					break
				fi
			done
		fi
		unset _old_dmm
		unset _init_system
	fi

	# Log setup
	mkdir -p "$inspath/logs" && touch "$logf"
	pkg_symlink "$logf" "$inspath/event_log"
	"$inspath/maldet" --alert-daily 2>/dev/null  # safe: primes digest state; no-op if no monitor running

	# Logrotate config — install only if logrotate is available
	if command -v logrotate >/dev/null 2>&1; then
		command cp -f ./files/logrotate.maldet /etc/logrotate.d/maldet
		command chmod 644 /etc/logrotate.d/maldet
	fi
}

# Installation summary

_postinfo() {
	echo ""
	pkg_item "Install path" "$inspath"
	pkg_item "Config file" "$inspath/conf.maldet"
	pkg_item "Exec file" "$inspath/maldet"
	pkg_item "Exec link" "/usr/local/sbin/maldet"
	pkg_item "Exec link" "/usr/local/sbin/lmd"
	pkg_item "Cron.daily" "/etc/cron.daily/maldet"
}

# Restart monitor if it was running

_restart_monitor() {
	if [ "${monmode:-}" == "1" ]; then
		if pkg_is_systemd && systemctl is-enabled maldet.service >/dev/null 2>&1; then
			pkg_info "restarting monitor via systemctl"
			systemctl restart maldet.service >>/dev/null 2>&1 &
		else
			pkg_info "restarting monitor with supervisor mode"
			"$inspath/maldet" -b -m users >>/dev/null 2>&1 &
		fi
	fi
}

# ══════════════════════════════════════════════════════════════════
# Main: fresh install vs upgrade
# ══════════════════════════════════════════════════════════════════

if [ -d "$inspath" ] && [ -d "files" ]; then
	# Upgrade path
	pkg_header "Linux Malware Detect" "$lmd_version" "upgrade"
	echo "            (C) 2002-2026, R-fx Networks <proj@rfxn.com>"
	echo "            (C) 2026, Ryan MacDonald <ryan@rfxn.com>"
	echo "This program may be freely redistributed under the terms of the GNU GPL v2"

	# Stop active monitor before backup (detect both supervisor and legacy modes)
	if [ -f "$inspath/tmp/monitor.pid" ]; then
		_mpid=$(command cat "$inspath/tmp/monitor.pid")
		if [ -n "$_mpid" ] && kill -0 "$_mpid" 2>/dev/null; then
			monmode=1
		fi
	fi
	if [ "${monmode:-}" != "1" ] && [ "$(ps -A --user root -o "command" 2>/dev/null | grep maldetect | grep inotifywait)" ]; then
		monmode=1
	fi
	if [ "${monmode:-}" == "1" ]; then
		"$inspath/maldet" -k >>/dev/null 2>&1
	fi

	pkg_section "Backing up existing installation"
	# One-time: prune old-format backups from pre-pkg_lib installations
	find "$(dirname "$inspath")" -maxdepth 1 -name "$(basename "$inspath").bk*" -type d -mtime +"$PKG_BACKUP_PRUNE_DAYS" -exec rm -rf {} + 2>/dev/null || true  # safe: old .bk* dirs may not exist
	# Prune new-format backups
	pkg_backup_prune "$inspath" "$PKG_BACKUP_PRUNE_DAYS"
	# Remove chattr locks before backup
	if command -v chattr >/dev/null 2>&1; then
		chattr -ia "$inspath/internals/internals.conf"
	fi
	# Create backup (move method — removes original)
	if ! pkg_backup "$inspath" "move"; then
		pkg_error "failed to backup $inspath, aborting install."
		exit 1
	fi
	# Resolve backup path for restore operations
	bkpath=$(pkg_backup_path "$inspath")

	pkg_section "Installing files"
	_install_core
	_migrate_logs
	_install_cron_service

	pkg_section "Importing configuration"
	BK_LAST="$bkpath" DEST_PREFIX="$inspath" "$inspath/internals/importconf"

	# Re-evaluate sigup_interval after config import (user may have set to 0)
	_post_sigup_interval=$(_read_conf_value "sigup_interval" "6")
	if [ "$_post_sigup_interval" = "0" ] || ! [ "$_post_sigup_interval" -gt 0 ] 2>/dev/null; then
		command rm -f /etc/cron.d/maldet-sigup 2>/dev/null  # safe: user disabled sigup
	fi
	unset _post_sigup_interval

	pkg_section "Updating signatures"
	"$inspath/maldet" --update 1

	_restart_monitor
	_postinfo
	pkg_success "Linux Malware Detect ${lmd_version} upgrade complete"

elif [ -d "files" ]; then
	# Fresh install path
	pkg_header "Linux Malware Detect" "$lmd_version" "install"
	echo "            (C) 2002-2026, R-fx Networks <proj@rfxn.com>"
	echo "            (C) 2026, Ryan MacDonald <ryan@rfxn.com>"
	echo "This program may be freely redistributed under the terms of the GNU GPL v2"

	pkg_section "Installing files"
	_install_core
	_migrate_logs
	# Create empty monitor_paths.extra if not restored from backup
	if [ ! -f "$inspath/monitor_paths.extra" ]; then
		touch "$inspath/monitor_paths.extra"
		chmod 640 "$inspath/monitor_paths.extra"
	fi
	_install_cron_service

	pkg_section "Updating signatures"
	"$inspath/maldet" --update 1

	_postinfo
	pkg_success "Linux Malware Detect ${lmd_version} installation complete"
fi
