#!/bin/bash
#
# pkg_lib.sh — Shared Packaging & Installer Library 1.0.8
###
# Copyright (C) 2002-2026 R-fx Networks <proj@rfxn.com>
#                         Ryan MacDonald <ryan@rfxn.com>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
###
#
# Shared packaging, install, and uninstall library for rfxn projects.
# Source this file after setting PKG_* configuration variables.
# No project-specific code — all behavior controlled via variables and arguments.

# Source guard — safe for repeated sourcing
# shellcheck disable=SC2154
[[ -n "${_PKG_LIB_LOADED:-}" ]] && return 0 2>/dev/null
_PKG_LIB_LOADED=1
# shellcheck disable=SC2034 # version checked by consumers
PKG_LIB_VERSION="1.0.9"

# Configurable defaults — consuming projects override via environment
PKG_NO_COLOR="${PKG_NO_COLOR:-0}"
PKG_QUIET="${PKG_QUIET:-0}"
PKG_TMPDIR="${PKG_TMPDIR:-${TMPDIR:-/tmp}}"

# Internal state — populated by detection functions, cached after first call
_PKG_C_RED=""
_PKG_C_GREEN=""
_PKG_C_YELLOW=""
_PKG_C_BOLD=""
_PKG_C_RESET=""
_PKG_COLOR_INIT_DONE=""

_PKG_OS_FAMILY=""
_PKG_OS_ID=""
_PKG_OS_VERSION=""
_PKG_OS_NAME=""
_PKG_OS_DETECT_DONE=""

_PKG_INIT_SYSTEM=""
_PKG_INIT_DETECT_DONE=""

_PKG_PKGMGR=""
_PKG_PKGMGR_DETECT_DONE=""

_PKG_DEPS_MISSING=0

# ══════════════════════════════════════════════════════════════════
# Section: Output & Messaging
# ══════════════════════════════════════════════════════════════════

# _pkg_color_init — detect terminal color support and set color variables
# Sets _PKG_C_RED, _PKG_C_GREEN, _PKG_C_YELLOW, _PKG_C_BOLD, _PKG_C_RESET.
# Non-terminal or PKG_NO_COLOR=1 → all empty strings.
# Cached: only runs once (idempotent on repeated calls).
_pkg_color_init() {
	# Already initialized — skip
	[[ -n "$_PKG_COLOR_INIT_DONE" ]] && return 0

	_PKG_COLOR_INIT_DONE=1
	_PKG_C_RED=""
	_PKG_C_GREEN=""
	_PKG_C_YELLOW=""
	_PKG_C_BOLD=""
	_PKG_C_RESET=""

	# Respect PKG_NO_COLOR override
	if [[ "${PKG_NO_COLOR:-0}" = "1" ]]; then
		return 0
	fi

	# Check if stdout is a terminal
	if [[ ! -t 1 ]]; then
		return 0
	fi

	# Check tput color support — graceful fallback if tput unavailable
	local colors
	colors=$(tput colors 2>/dev/null) || return 0
	if [[ "$colors" -ge 8 ]] 2>/dev/null; then
		_PKG_C_RED=$(tput setaf 1 2>/dev/null) || _PKG_C_RED=""
		_PKG_C_GREEN=$(tput setaf 2 2>/dev/null) || _PKG_C_GREEN=""
		_PKG_C_YELLOW=$(tput setaf 3 2>/dev/null) || _PKG_C_YELLOW=""
		_PKG_C_BOLD=$(tput bold 2>/dev/null) || _PKG_C_BOLD=""
		_PKG_C_RESET=$(tput sgr0 2>/dev/null) || _PKG_C_RESET=""
	fi

	return 0
}

# pkg_header project_name version action — print styled install/uninstall header
# Arguments:
#   $1 — project name (e.g., "BFD", "APF")
#   $2 — version string (e.g., "2.0.1")
#   $3 — action (e.g., "install", "uninstall", "upgrade")
pkg_header() {
	local project="$1" version="$2" action="$3"
	if [[ -z "$project" ]] || [[ -z "$version" ]]; then
		echo "pkg_lib: pkg_header requires project_name and version" >&2
		return 1
	fi
	local header_text="${project} ${version}"
	if [[ -n "$action" ]]; then
		header_text="${header_text} — ${action}"
	fi
	_pkg_color_init
	echo ""
	echo "${_PKG_C_BOLD}:: ${header_text}${_PKG_C_RESET}"
	echo "---------------------------------------------------------------"
	return 0
}

# pkg_info message — print info message with consistent prefix
# Suppressed when PKG_QUIET=1.
pkg_info() {
	local msg="$1"
	if [[ "${PKG_QUIET:-0}" = "1" ]]; then
		return 0
	fi
	_pkg_color_init
	echo "  ${msg}"
	return 0
}

# pkg_warn message — print warning to stderr (yellow if terminal)
pkg_warn() {
	local msg="$1"
	_pkg_color_init
	echo "${_PKG_C_YELLOW}  warning: ${msg}${_PKG_C_RESET}" >&2
	return 0
}

# pkg_error message — print error to stderr (red if terminal)
pkg_error() {
	local msg="$1"
	_pkg_color_init
	echo "${_PKG_C_RED}  error: ${msg}${_PKG_C_RESET}" >&2
	return 0
}

# pkg_success message — print success message (green if terminal)
pkg_success() {
	local msg="$1"
	_pkg_color_init
	echo "${_PKG_C_GREEN}  ${msg}${_PKG_C_RESET}"
	return 0
}

# pkg_section title — print section separator with title
pkg_section() {
	local title="$1"
	if [[ -z "$title" ]]; then
		echo "pkg_lib: pkg_section requires a title" >&2
		return 1
	fi
	_pkg_color_init
	echo ""
	echo "${_PKG_C_BOLD}  [ ${title} ]${_PKG_C_RESET}"
	return 0
}

# pkg_item label value — print aligned key: value pair
# Arguments:
#   $1 — label (left side)
#   $2 — value (right side)
pkg_item() {
	local label="$1" value="$2"
	printf "  %-20s %s\n" "${label}:" "$value"
	return 0
}

# ══════════════════════════════════════════════════════════════════
# Section: OS & Platform Detection
# ══════════════════════════════════════════════════════════════════

# pkg_detect_os — detect operating system family, ID, version, and display name
# Sets: _PKG_OS_FAMILY, _PKG_OS_ID, _PKG_OS_VERSION, _PKG_OS_NAME
# Detection chain: /etc/os-release → /etc/redhat-release → /etc/debian_version →
#   /etc/gentoo-release → /etc/slackware-version → uname -s (FreeBSD)
# Cached: only runs once.
pkg_detect_os() {
	# Already detected — skip
	[[ -n "$_PKG_OS_DETECT_DONE" ]] && return 0
	_PKG_OS_DETECT_DONE=1

	_PKG_OS_FAMILY="unknown"
	_PKG_OS_ID="unknown"
	_PKG_OS_VERSION=""
	_PKG_OS_NAME="unknown"

	# Primary: /etc/os-release (modern distros)
	if [[ -f /etc/os-release ]]; then
		local line key val
		while IFS= read -r line; do
			# Skip comments and blank lines
			[[ "$line" =~ ^[[:space:]]*# ]] && continue
			[[ -z "$line" ]] && continue
			# Parse KEY=VALUE (strip quotes)
			key="${line%%=*}"
			val="${line#*=}"
			val="${val#\"}"
			val="${val%\"}"
			val="${val#\'}"
			val="${val%\'}"
			case "$key" in
				ID)         _PKG_OS_ID="$val" ;;
				VERSION_ID) _PKG_OS_VERSION="$val" ;;
				ID_LIKE)
					# Map ID_LIKE to family
					case "$val" in
						*rhel*|*centos*|*fedora*) _PKG_OS_FAMILY="rhel" ;;
						*debian*)                 _PKG_OS_FAMILY="debian" ;;
					esac
					;;
				PRETTY_NAME) _PKG_OS_NAME="$val" ;;
			esac
		done < /etc/os-release

		# Derive family from ID if ID_LIKE did not set it
		if [[ "$_PKG_OS_FAMILY" = "unknown" ]]; then
			case "$_PKG_OS_ID" in
				centos|rhel|rocky|alma|fedora|ol|amzn) _PKG_OS_FAMILY="rhel" ;;
				debian|ubuntu|linuxmint|raspbian)      _PKG_OS_FAMILY="debian" ;;
				gentoo)                                 _PKG_OS_FAMILY="gentoo" ;;
				slackware)                              _PKG_OS_FAMILY="slackware" ;;
			esac
		fi

		# Fallback name
		if [[ "$_PKG_OS_NAME" = "unknown" ]]; then
			_PKG_OS_NAME="${_PKG_OS_ID} ${_PKG_OS_VERSION}"
		fi
		return 0
	fi

	# Fallback: /etc/redhat-release
	if [[ -f /etc/redhat-release ]]; then
		_PKG_OS_FAMILY="rhel"
		_PKG_OS_NAME=$(cat /etc/redhat-release 2>/dev/null) || _PKG_OS_NAME="RHEL-family"
		# Extract version number (first numeric sequence with optional dots)
		local ver_pat='[0-9]+(\.[0-9]+)*'
		if [[ "$_PKG_OS_NAME" =~ $ver_pat ]]; then
			_PKG_OS_VERSION="${BASH_REMATCH[0]}"
		fi
		# Extract distro ID
		local id_lower
		id_lower=$(echo "$_PKG_OS_NAME" | tr '[:upper:]' '[:lower:]')
		case "$id_lower" in
			centos*)  _PKG_OS_ID="centos" ;;
			red*)     _PKG_OS_ID="rhel" ;;
			rocky*)   _PKG_OS_ID="rocky" ;;
			alma*)    _PKG_OS_ID="alma" ;;
			fedora*)  _PKG_OS_ID="fedora" ;;
			*)        _PKG_OS_ID="rhel" ;;
		esac
		return 0
	fi

	# Fallback: /etc/debian_version
	if [[ -f /etc/debian_version ]]; then
		_PKG_OS_FAMILY="debian"
		_PKG_OS_ID="debian"
		_PKG_OS_VERSION=$(cat /etc/debian_version 2>/dev/null) || _PKG_OS_VERSION=""
		_PKG_OS_NAME="Debian ${_PKG_OS_VERSION}"
		return 0
	fi

	# Fallback: /etc/gentoo-release
	if [[ -f /etc/gentoo-release ]]; then
		_PKG_OS_FAMILY="gentoo"
		_PKG_OS_ID="gentoo"
		_PKG_OS_NAME=$(cat /etc/gentoo-release 2>/dev/null) || _PKG_OS_NAME="Gentoo"
		return 0
	fi

	# Fallback: /etc/slackware-version
	if [[ -f /etc/slackware-version ]]; then
		_PKG_OS_FAMILY="slackware"
		_PKG_OS_ID="slackware"
		_PKG_OS_NAME=$(cat /etc/slackware-version 2>/dev/null) || _PKG_OS_NAME="Slackware"
		local ver_pat='[0-9]+(\.[0-9]+)*'
		if [[ "$_PKG_OS_NAME" =~ $ver_pat ]]; then
			_PKG_OS_VERSION="${BASH_REMATCH[0]}"
		fi
		return 0
	fi

	# Fallback: uname -s (FreeBSD)
	local uname_s
	uname_s=$(uname -s 2>/dev/null) || uname_s=""
	case "$uname_s" in
		FreeBSD)
			_PKG_OS_FAMILY="freebsd"
			_PKG_OS_ID="freebsd"
			_PKG_OS_VERSION=$(uname -r 2>/dev/null) || _PKG_OS_VERSION=""
			_PKG_OS_NAME="FreeBSD ${_PKG_OS_VERSION}"
			;;
	esac

	return 0
}

# pkg_detect_init — detect init system
# Sets: _PKG_INIT_SYSTEM (systemd|sysv|upstart|rc.local|unknown)
# Detection chain: /run/systemd/system dir → /proc/1/comm → rc.local
# Cached: only runs once.
pkg_detect_init() {
	# Already detected — skip
	[[ -n "$_PKG_INIT_DETECT_DONE" ]] && return 0
	_PKG_INIT_DETECT_DONE=1

	_PKG_INIT_SYSTEM="unknown"

	# systemd: check for /run/systemd/system directory
	if [[ -d /run/systemd/system ]]; then
		_PKG_INIT_SYSTEM="systemd"
		return 0
	fi

	# Check /proc/1/comm if it exists (may not on CentOS 6)
	if [[ -f /proc/1/comm ]]; then
		local pid1_comm
		pid1_comm=$(cat /proc/1/comm 2>/dev/null) || pid1_comm=""
		case "$pid1_comm" in
			systemd)  _PKG_INIT_SYSTEM="systemd" ;;
			init)     _PKG_INIT_SYSTEM="sysv" ;;
			upstart)  _PKG_INIT_SYSTEM="upstart" ;;
		esac
		if [[ "$_PKG_INIT_SYSTEM" != "unknown" ]]; then
			return 0
		fi
	fi

	# Fallback: if /etc/init.d exists, likely SysV
	if [[ -d /etc/init.d ]] || [[ -d /etc/rc.d/init.d ]]; then
		_PKG_INIT_SYSTEM="sysv"
		return 0
	fi

	# Last resort: rc.local
	if [[ -f /etc/rc.local ]] || [[ -f /etc/rc.d/rc.local ]]; then
		_PKG_INIT_SYSTEM="rc.local"
		return 0
	fi

	return 0
}

# pkg_detect_pkgmgr — detect package manager
# Sets: _PKG_PKGMGR (dnf|yum|apt|emerge|pkg|slackpkg|unknown)
# Uses command -v cascade. Cached: only runs once.
pkg_detect_pkgmgr() {
	# Already detected — skip
	[[ -n "$_PKG_PKGMGR_DETECT_DONE" ]] && return 0
	_PKG_PKGMGR_DETECT_DONE=1

	_PKG_PKGMGR="unknown"

	if command -v dnf >/dev/null 2>&1; then
		_PKG_PKGMGR="dnf"
	elif command -v yum >/dev/null 2>&1; then
		_PKG_PKGMGR="yum"
	elif command -v apt-get >/dev/null 2>&1; then
		_PKG_PKGMGR="apt"
	elif command -v emerge >/dev/null 2>&1; then
		_PKG_PKGMGR="emerge"
	elif command -v pkg >/dev/null 2>&1; then
		_PKG_PKGMGR="pkg"
	elif command -v slackpkg >/dev/null 2>&1; then
		_PKG_PKGMGR="slackpkg"
	fi

	return 0
}

# pkg_is_systemd — return 0 if systemd is the init system
# Calls pkg_detect_init if not already done.
pkg_is_systemd() {
	pkg_detect_init
	[[ "$_PKG_INIT_SYSTEM" = "systemd" ]]
}

# pkg_os_family — echo OS family and return 0
# Calls pkg_detect_os if not already done.
# Outputs: rhel|debian|gentoo|slackware|freebsd|unknown
pkg_os_family() {
	pkg_detect_os
	echo "$_PKG_OS_FAMILY"
	return 0
}

# ══════════════════════════════════════════════════════════════════
# Section: Dependency Checking
# ══════════════════════════════════════════════════════════════════

# pkg_dep_hint pkg_rpm pkg_deb — print package-manager-specific install command
# Arguments:
#   $1 — RPM package name
#   $2 — DEB package name
# Uses _PKG_PKGMGR to select the right hint. Calls pkg_detect_pkgmgr if needed.
pkg_dep_hint() {
	local pkg_rpm="$1" pkg_deb="$2"
	pkg_detect_pkgmgr

	local hint=""
	case "$_PKG_PKGMGR" in
		dnf)      hint="dnf install ${pkg_rpm}" ;;
		yum)      hint="yum install ${pkg_rpm}" ;;
		apt)      hint="apt-get install ${pkg_deb}" ;;
		emerge)   hint="emerge ${pkg_rpm}" ;;
		pkg)      hint="pkg install ${pkg_rpm}" ;;
		slackpkg) hint="slackpkg install ${pkg_rpm}" ;;
		*)        hint="install package providing this binary" ;;
	esac
	echo "$hint"
	return 0
}

# pkg_check_dep binary pkg_rpm pkg_deb level — check a single dependency
# Arguments:
#   $1 — binary name to check (via command -v)
#   $2 — RPM package name (for install hint)
#   $3 — DEB package name (for install hint)
#   $4 — level: required|recommended|optional
# Returns 0 if found, 1 if missing.
# Side effects: sets _PKG_DEPS_MISSING=1 for required deps.
pkg_check_dep() {
	local binary="$1" pkg_rpm="$2" pkg_deb="$3" level="${4:-required}"

	if [[ -z "$binary" ]]; then
		echo "pkg_lib: pkg_check_dep requires binary name" >&2
		return 1
	fi

	# Binary found — pass
	if command -v "$binary" >/dev/null 2>&1; then
		return 0
	fi

	# Binary missing — report based on level
	local hint
	hint=$(pkg_dep_hint "$pkg_rpm" "$pkg_deb")

	case "$level" in
		required)
			_PKG_DEPS_MISSING=1
			pkg_error "missing required dependency: ${binary}"
			pkg_info "  install: ${hint}"
			;;
		recommended)
			pkg_warn "missing recommended dependency: ${binary}"
			pkg_info "  install: ${hint}"
			;;
		optional)
			pkg_info "optional dependency not found: ${binary} (${hint})"
			;;
		*)
			pkg_warn "unknown dependency level '${level}' for ${binary}"
			;;
	esac

	return 1
}

# pkg_check_deps prefix — batch check dependencies from parallel arrays
# Arguments:
#   $1 — variable name prefix for arrays (e.g., "MY_APP" looks for
#         ${MY_APP_DEP_BINS[@]}, ${MY_APP_DEP_RPMS[@]},
#         ${MY_APP_DEP_DEBS[@]}, ${MY_APP_DEP_LEVELS[@]})
# Returns 0 if all found, 1 if any missing required deps.
# Uses indirect expansion compatible with bash 4.1.
pkg_check_deps() {
	local prefix="$1"

	if [[ -z "$prefix" ]]; then
		echo "pkg_lib: pkg_check_deps requires a variable prefix" >&2
		return 1
	fi

	# Build indirect references for bash 4.1 compat (no declare -n)
	local bins_ref="${prefix}_DEP_BINS[@]"
	local rpms_ref="${prefix}_DEP_RPMS[@]"
	local debs_ref="${prefix}_DEP_DEBS[@]"
	local levels_ref="${prefix}_DEP_LEVELS[@]"

	# Copy into local indexed arrays
	local bins=("${!bins_ref}")
	local rpms=("${!rpms_ref}")
	local debs=("${!debs_ref}")
	local levels=("${!levels_ref}")

	if [[ ${#bins[@]} -eq 0 ]]; then
		return 0
	fi

	local i
	local any_missing=0
	for i in "${!bins[@]}"; do
		pkg_check_dep "${bins[$i]}" "${rpms[$i]:-}" "${debs[$i]:-}" "${levels[$i]:-required}" || any_missing=1
	done

	return "$any_missing"
}

# ══════════════════════════════════════════════════════════════════
# Section: Backup & Restore
# ══════════════════════════════════════════════════════════════════

# Configurable defaults — consuming projects override via environment
PKG_BACKUP_METHOD="${PKG_BACKUP_METHOD:-move}"
PKG_BACKUP_SYMLINK="${PKG_BACKUP_SYMLINK:-.bk.last}"
PKG_BACKUP_PRUNE_DAYS="${PKG_BACKUP_PRUNE_DAYS:-0}"

# pkg_backup install_path [method] — create timestamped backup of install_path
# Arguments:
#   $1 — install path to back up (must exist)
#   $2 — method: "copy" (cp -R, original stays) or "move" (mv, original removed)
#         Defaults to PKG_BACKUP_METHOD env var (default: move)
# Backup naming: <install_path>.<DDMMYYYY-EPOCH>
# Collision safety: appends -N suffix if target already exists.
# Creates PKG_BACKUP_SYMLINK (default .bk.last) pointing to latest backup.
# Returns 1 on failure.
pkg_backup() {
	local install_path="$1"
	local method="${2:-${PKG_BACKUP_METHOD}}"

	if [[ -z "$install_path" ]]; then
		pkg_error "pkg_backup: install_path required"
		return 1
	fi

	if [[ ! -e "$install_path" ]]; then
		pkg_error "pkg_backup: install path does not exist: ${install_path}"
		return 1
	fi

	# Validate method
	case "$method" in
		copy|move) ;;
		*)
			pkg_error "pkg_backup: invalid method '${method}' (must be copy or move)"
			return 1
			;;
	esac

	# Build timestamp: DDMMYYYY-EPOCH
	local timestamp
	timestamp="$(date +%d%m%Y)-$(date +%s)"

	local backup_path="${install_path}.${timestamp}"

	# Collision safety — append -N if target exists
	if [[ -e "$backup_path" ]]; then
		local suffix=1
		while [[ -e "${backup_path}-${suffix}" ]]; do
			suffix=$((suffix + 1))
		done
		backup_path="${backup_path}-${suffix}"
	fi

	# Perform backup
	local rc=0
	case "$method" in
		copy)
			command cp -pR "$install_path" "$backup_path" || rc=$?
			;;
		move)
			command mv "$install_path" "$backup_path" || rc=$?
			;;
	esac

	if [[ "$rc" -ne 0 ]]; then
		pkg_error "pkg_backup: failed to ${method} ${install_path} to ${backup_path}"
		return 1
	fi

	# Update .bk.last symlink (or configured name)
	local symlink_path
	symlink_path="$(dirname "$install_path")/${PKG_BACKUP_SYMLINK}"
	command rm -f "$symlink_path"
	ln -s "$backup_path" "$symlink_path" || {
		pkg_warn "pkg_backup: failed to create symlink ${symlink_path}"
	}

	pkg_info "backup created: ${backup_path}"
	return 0
}

# pkg_backup_exists install_path — return 0 if .bk.last symlink exists
# Arguments:
#   $1 — install path (symlink is looked up in its parent directory)
pkg_backup_exists() {
	local install_path="$1"

	if [[ -z "$install_path" ]]; then
		pkg_error "pkg_backup_exists: install_path required"
		return 1
	fi

	local symlink_path
	symlink_path="$(dirname "$install_path")/${PKG_BACKUP_SYMLINK}"
	[[ -L "$symlink_path" ]]
}

# pkg_backup_path install_path — echo resolved path of .bk.last symlink
# Arguments:
#   $1 — install path (symlink is looked up in its parent directory)
# Returns 1 if symlink does not exist.
pkg_backup_path() {
	local install_path="$1"

	if [[ -z "$install_path" ]]; then
		pkg_error "pkg_backup_path: install_path required"
		return 1
	fi

	local symlink_path
	symlink_path="$(dirname "$install_path")/${PKG_BACKUP_SYMLINK}"

	if [[ ! -L "$symlink_path" ]]; then
		pkg_error "pkg_backup_path: no backup symlink found: ${symlink_path}"
		return 1
	fi

	# Resolve symlink target
	local target
	target=$(readlink "$symlink_path") || {
		pkg_error "pkg_backup_path: failed to read symlink: ${symlink_path}"
		return 1
	}
	echo "$target"
	return 0
}

# pkg_backup_prune install_path max_age_days — remove backups older than N days
# Arguments:
#   $1 — install path (backups are <install_path>.<timestamp> in parent dir)
#   $2 — max age in days (0 = no pruning)
# Removes matching backup directories/files older than max_age_days.
# Does not remove the .bk.last symlink target.
# Returns 0 on success, 1 on invalid arguments.
pkg_backup_prune() {
	local install_path="$1"
	local max_age_days="$2"

	if [[ -z "$install_path" ]] || [[ -z "$max_age_days" ]]; then
		pkg_error "pkg_backup_prune: install_path and max_age_days required"
		return 1
	fi

	# Validate max_age_days is a non-negative integer
	local int_pat='^[0-9]+$'
	if ! [[ "$max_age_days" =~ $int_pat ]]; then
		pkg_error "pkg_backup_prune: max_age_days must be a positive integer"
		return 1
	fi

	# 0 = no pruning
	if [[ "$max_age_days" -eq 0 ]]; then
		return 0
	fi

	local parent_dir
	parent_dir="$(dirname "$install_path")"
	local base_name
	base_name="$(basename "$install_path")"

	# Resolve current .bk.last target so we never prune it
	local current_backup=""
	local symlink_path="${parent_dir}/${PKG_BACKUP_SYMLINK}"
	if [[ -L "$symlink_path" ]]; then
		current_backup=$(readlink "$symlink_path" 2>/dev/null) || current_backup=""
	fi

	# Find backup entries matching the pattern: <base_name>.<digits>-<digits>*
	local bk_pat="^${base_name}\.[0-9]{8}-[0-9]+"
	local pruned=0
	local entry entry_path
	while IFS= read -r entry; do
		[[ -z "$entry" ]] && continue
		if ! [[ "$entry" =~ $bk_pat ]]; then
			continue
		fi
		entry_path="${parent_dir}/${entry}"

		# Skip if this is the current backup target
		if [[ -n "$current_backup" ]] && [[ "$entry_path" = "$current_backup" ]]; then
			continue
		fi

		# Check age using find -maxdepth 0 -mtime
		if find "$entry_path" -maxdepth 0 -mtime +"$max_age_days" -print 2>/dev/null | read -r _; then
			command rm -rf "$entry_path"
			pruned=$((pruned + 1))
		fi
	done <<< "$(find "$parent_dir" -maxdepth 1 -mindepth 1 -printf '%f\n' 2>/dev/null)"

	if [[ "$pruned" -gt 0 ]]; then
		pkg_info "pruned ${pruned} old backup(s)"
	fi

	return 0
}

# pkg_restore_files backup_path install_path patterns... — selective file restore
# Arguments:
#   $1 — backup path (source directory)
#   $2 — install path (destination directory)
#   $3+ — glob patterns to restore (e.g., "conf.*" "*.rules")
# Copies matching files from backup to install path, preserving attributes.
# Returns 1 on failure.
pkg_restore_files() {
	local backup_path="$1"
	local install_path="$2"
	shift 2

	if [[ -z "$backup_path" ]] || [[ -z "$install_path" ]]; then
		pkg_error "pkg_restore_files: backup_path and install_path required"
		return 1
	fi

	if [[ $# -eq 0 ]]; then
		pkg_error "pkg_restore_files: at least one glob pattern required"
		return 1
	fi

	if [[ ! -d "$backup_path" ]]; then
		pkg_error "pkg_restore_files: backup path not found: ${backup_path}"
		return 1
	fi

	# Create install path if it does not exist
	if [[ ! -d "$install_path" ]]; then
		mkdir -p "$install_path" || {
			pkg_error "pkg_restore_files: failed to create ${install_path}"
			return 1
		}
	fi

	local pattern restored=0 rc
	for pattern in "$@"; do
		# Use find with -name for each pattern (avoids glob expansion issues)
		while IFS= read -r match; do
			[[ -z "$match" ]] && continue
			# Compute relative path from backup_path
			local relpath="${match#"${backup_path}"/}"
			local dest="${install_path}/${relpath}"
			local dest_dir
			dest_dir="$(dirname "$dest")"

			# Ensure destination directory exists
			if [[ ! -d "$dest_dir" ]]; then
				mkdir -p "$dest_dir" || continue
			fi

			rc=0
			command cp -p "$match" "$dest" || rc=$?
			if [[ "$rc" -eq 0 ]]; then
				restored=$((restored + 1))
			else
				pkg_warn "pkg_restore_files: failed to restore ${relpath}"
			fi
		done <<< "$(find "$backup_path" -name "$pattern" -not -type d 2>/dev/null)"
	done

	if [[ "$restored" -eq 0 ]]; then
		pkg_warn "pkg_restore_files: no files matched the given patterns"
		return 1
	fi

	pkg_info "restored ${restored} file(s)"
	return 0
}

# pkg_restore_dir backup_path install_path subdir — restore entire subdirectory
# Arguments:
#   $1 — backup path (source root)
#   $2 — install path (destination root)
#   $3 — subdirectory name to restore (relative to backup/install)
# Copies the entire subdirectory from backup to install path.
# Returns 1 on failure.
pkg_restore_dir() {
	local backup_path="$1"
	local install_path="$2"
	local subdir="$3"

	if [[ -z "$backup_path" ]] || [[ -z "$install_path" ]] || [[ -z "$subdir" ]]; then
		pkg_error "pkg_restore_dir: backup_path, install_path, and subdir required"
		return 1
	fi

	local src="${backup_path}/${subdir}"

	if [[ ! -d "$src" ]]; then
		pkg_error "pkg_restore_dir: subdirectory not found in backup: ${subdir}"
		return 1
	fi

	local dest="${install_path}/${subdir}"
	local dest_parent
	dest_parent="$(dirname "$dest")"

	# Ensure destination parent directory exists
	if [[ ! -d "$dest_parent" ]]; then
		mkdir -p "$dest_parent" || {
			pkg_error "pkg_restore_dir: failed to create ${dest_parent}"
			return 1
		}
	fi

	command cp -pR "$src" "$dest" || {
		pkg_error "pkg_restore_dir: failed to restore ${subdir}"
		return 1
	}

	pkg_info "restored directory: ${subdir}"
	return 0
}

# ══════════════════════════════════════════════════════════════════
# Section: File Operations
# ══════════════════════════════════════════════════════════════════

# pkg_copy_tree src_dir dest_dir — recursive copy with attribute preservation
# Arguments:
#   $1 — source directory
#   $2 — destination directory
# Uses cp -pR to preserve ownership, permissions, timestamps.
# Returns 1 on failure.
pkg_copy_tree() {
	local src_dir="$1"
	local dest_dir="$2"

	if [[ -z "$src_dir" ]] || [[ -z "$dest_dir" ]]; then
		pkg_error "pkg_copy_tree: src_dir and dest_dir required"
		return 1
	fi

	if [[ ! -d "$src_dir" ]]; then
		pkg_error "pkg_copy_tree: source directory not found: ${src_dir}"
		return 1
	fi

	# Create destination if it does not exist
	if [[ ! -d "$dest_dir" ]]; then
		mkdir -p "$dest_dir" || {
			pkg_error "pkg_copy_tree: failed to create ${dest_dir}"
			return 1
		}
	fi

	command cp -pR "${src_dir}/." "$dest_dir/" || {
		pkg_error "pkg_copy_tree: failed to copy ${src_dir} to ${dest_dir}"
		return 1
	}

	return 0
}

# pkg_set_perms path dir_mode file_mode [exec_files...] — set permissions
# Arguments:
#   $1 — base path to set permissions on
#   $2 — mode for directories (e.g., "750")
#   $3 — mode for regular files (e.g., "640")
#   $4+ — executable files (relative to path) to set to exec_mode (same as dir_mode)
# Sets directory permissions, then file permissions, then executable overrides.
# Returns 1 on failure.
pkg_set_perms() {
	local base_path="$1"
	local dir_mode="$2"
	local file_mode="$3"
	shift 3

	if [[ -z "$base_path" ]] || [[ -z "$dir_mode" ]] || [[ -z "$file_mode" ]]; then
		pkg_error "pkg_set_perms: base_path, dir_mode, and file_mode required"
		return 1
	fi

	if [[ ! -e "$base_path" ]]; then
		pkg_error "pkg_set_perms: path does not exist: ${base_path}"
		return 1
	fi

	# Set directory permissions
	find "$base_path" -type d -exec chmod "$dir_mode" {} + 2>/dev/null  # best-effort: traversal errors on restricted dirs safe to ignore

	# Set regular file permissions
	find "$base_path" -type f -exec chmod "$file_mode" {} + 2>/dev/null  # best-effort: traversal errors on restricted dirs safe to ignore

	# Override executable files (use dir_mode as executable mode)
	local exec_file
	for exec_file in "$@"; do
		local full_path="${base_path}/${exec_file}"
		if [[ -f "$full_path" ]]; then
			chmod "$dir_mode" "$full_path" || {
				pkg_warn "pkg_set_perms: failed to set exec mode on ${exec_file}"
			}
		fi
	done

	return 0
}

# pkg_create_dirs mode dirs... — create directories with specified mode
# Arguments:
#   $1 — mode (e.g., "750")
#   $2+ — directory paths to create
# Returns 1 if any creation fails.
pkg_create_dirs() {
	local mode="$1"
	shift

	if [[ -z "$mode" ]] || [[ $# -eq 0 ]]; then
		pkg_error "pkg_create_dirs: mode and at least one directory required"
		return 1
	fi

	local dir rc=0
	for dir in "$@"; do
		if [[ ! -d "$dir" ]]; then
			mkdir -p "$dir" || {
				pkg_error "pkg_create_dirs: failed to create ${dir}"
				rc=1
				continue
			}
		fi
		chmod "$mode" "$dir" || {
			pkg_warn "pkg_create_dirs: failed to set mode ${mode} on ${dir}"
		}
	done

	return "$rc"
}

# pkg_symlink target link_path — create or update a symbolic link
# Arguments:
#   $1 — target (what the link points to)
#   $2 — link path (the symlink to create)
# Removes existing link/file at link_path before creating.
# Returns 1 on failure.
pkg_symlink() {
	local target="$1"
	local link_path="$2"

	if [[ -z "$target" ]] || [[ -z "$link_path" ]]; then
		pkg_error "pkg_symlink: target and link_path required"
		return 1
	fi

	# Reduced TOCTOU: ln -sfn replaces rm+ln with a single coreutils call
	# -n prevents following existing symlink-to-directory (classic ln -sf gotcha)
	command ln -sfn "$target" "$link_path" || {
		pkg_error "pkg_symlink: failed to create symlink ${link_path} -> ${target}"
		return 1
	}

	return 0
}

# pkg_symlink_cleanup link_paths... — remove symlinks only (safety: skip non-symlinks)
# Arguments:
#   $1+ — symlink paths to remove
# Silently skips paths that are not symlinks (safety measure).
# Returns 0 always.
pkg_symlink_cleanup() {
	if [[ $# -eq 0 ]]; then
		pkg_error "pkg_symlink_cleanup: at least one link path required"
		return 1
	fi

	local link_path
	for link_path in "$@"; do
		if [[ -L "$link_path" ]]; then
			command rm -f "$link_path"
		elif [[ -e "$link_path" ]]; then
			pkg_warn "pkg_symlink_cleanup: skipping non-symlink: ${link_path}"
		fi
	done

	return 0
}

# pkg_sed_replace old_path new_path files... — sed -i path replacement across files
# Arguments:
#   $1 — old path string to replace
#   $2 — new path string to substitute
#   $3+ — files to perform replacement on
# Uses '|' as sed delimiter to avoid conflicts with path separators.
# Returns 1 if no files provided.
pkg_sed_replace() {
	local old_path="$1"
	local new_path="$2"
	shift 2

	if [[ -z "$old_path" ]] || [[ -z "$new_path" ]]; then
		pkg_error "pkg_sed_replace: old_path and new_path required"
		return 1
	fi

	if [[ $# -eq 0 ]]; then
		pkg_error "pkg_sed_replace: at least one file required"
		return 1
	fi

	# Escape old_path for BRE search: .*[\^$&|/\ must be escaped
	# Escape new_path for sed replacement: &|/\ only
	local esc_old esc_new
	esc_old=$(printf '%s' "$old_path" | sed 's/[.*[\^$&|/\\]/\\&/g')
	esc_new=$(printf '%s' "$new_path" | sed 's/[&|/\\]/\\&/g')

	local file
	for file in "$@"; do
		if [[ ! -f "$file" ]]; then
			pkg_warn "pkg_sed_replace: file not found, skipping: ${file}"
			continue
		fi
		sed -i "s|${esc_old}|${esc_new}|g" "$file" || {
			pkg_warn "pkg_sed_replace: sed failed on ${file}"
		}
	done

	return 0
}

# pkg_tmpfile [template] — mktemp wrapper with default template
# Arguments:
#   $1 — optional mktemp template (default: pkg_lib.XXXXXXXXXX)
# Creates temp file in PKG_TMPDIR. Echoes path to stdout.
# Returns 1 on failure.
pkg_tmpfile() {
	local template="${1:-pkg_lib.XXXXXXXXXX}"

	local tmpfile
	tmpfile=$(mktemp "${PKG_TMPDIR}/${template}") || {
		pkg_error "pkg_tmpfile: mktemp failed"
		return 1
	}

	echo "$tmpfile"
	return 0
}

# ══════════════════════════════════════════════════════════════════
# Section: Service Lifecycle
# ══════════════════════════════════════════════════════════════════

# --- Environment defaults ---
PKG_CHKCONFIG_LEVELS="${PKG_CHKCONFIG_LEVELS:-345}"
PKG_UPDATERCD_START="${PKG_UPDATERCD_START:-95}"
PKG_UPDATERCD_STOP="${PKG_UPDATERCD_STOP:-05}"
PKG_SYSTEMD_UNIT_DIR="${PKG_SYSTEMD_UNIT_DIR:-}"          # empty = auto-detect
PKG_SLACKWARE_RUNLEVELS="${PKG_SLACKWARE_RUNLEVELS:-2 3 4 5}"
PKG_SLACKWARE_PRIORITY="${PKG_SLACKWARE_PRIORITY:-95}"

# Private: rc.local search paths (override in tests)
_PKG_RCLOCAL_PATHS="${_PKG_RCLOCAL_PATHS:-/etc/rc.local /etc/rc.d/rc.local}"

# --- Internal helpers ---

# _pkg_systemd_unit_dir — resolve systemd unit directory
# Priority: PKG_SYSTEMD_UNIT_DIR env var → /usr/lib/systemd/system → /lib/systemd/system
# Returns 1 if no directory found.
_pkg_systemd_unit_dir() {
	# Env var override
	if [[ -n "$PKG_SYSTEMD_UNIT_DIR" ]]; then
		echo "$PKG_SYSTEMD_UNIT_DIR"
		return 0
	fi

	# Auto-detect: RHEL-family first, then Debian-family
	if [[ -d /usr/lib/systemd/system ]]; then
		echo "/usr/lib/systemd/system"
		return 0
	fi
	if [[ -d /lib/systemd/system ]]; then
		echo "/lib/systemd/system"
		return 0
	fi

	return 1
}

# _pkg_init_script_path name — resolve SysV init script path
# Arguments:
#   $1 — service name
# Checks /etc/rc.d/init.d/$name then /etc/init.d/$name.
# Returns 1 if neither exists.
_pkg_init_script_path() {
	local name="$1"

	if [[ -f "/etc/rc.d/init.d/${name}" ]]; then
		echo "/etc/rc.d/init.d/${name}"
		return 0
	fi
	if [[ -f "/etc/init.d/${name}" ]]; then
		echo "/etc/init.d/${name}"
		return 0
	fi

	return 1
}

# _pkg_service_ctl action name — shared start/stop/restart cascade
# Arguments:
#   $1 — action (start|stop|restart)
#   $2 — service name
# Cascade: systemd → SysV init script → error
# Returns 1 if no init method found.
_pkg_service_ctl() {
	local action="$1" name="$2"

	# systemd path
	if command -v systemctl >/dev/null 2>&1; then
		systemctl "$action" "$name" 2>/dev/null  # may fail if unit missing
		return $?
	fi

	# SysV path
	local init_script
	if init_script=$(_pkg_init_script_path "$name"); then
		"$init_script" "$action"
		return $?
	fi

	pkg_error "no init method found for service: ${name}"
	return 1
}

# --- Service install/uninstall ---

# pkg_service_install name source_file — install unit or init script
# Arguments:
#   $1 — service name
#   $2 — source file path (unit file or init script)
# Copies to correct location based on detected init system.
# For systemd: copies to unit dir, runs daemon-reload.
# For SysV: copies to init.d, chmod 755.
# Returns 1 on failure.
pkg_service_install() {
	local name="$1" source_file="$2"

	if [[ -z "$name" ]] || [[ -z "$source_file" ]]; then
		pkg_error "pkg_service_install: name and source_file required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	if [[ ! -f "$source_file" ]]; then
		pkg_error "pkg_service_install: source file not found: ${source_file}"
		return 1
	fi

	pkg_detect_init

	if [[ "$_PKG_INIT_SYSTEM" = "systemd" ]]; then
		local unit_dir
		if ! unit_dir=$(_pkg_systemd_unit_dir); then
			pkg_error "pkg_service_install: cannot locate systemd unit directory"
			return 1
		fi
		local basename_file
		basename_file=$(basename "$source_file")
		command cp -f "$source_file" "${unit_dir}/${basename_file}" || {
			pkg_error "pkg_service_install: failed to copy unit file to ${unit_dir}"
			return 1
		}
		systemctl daemon-reload 2>/dev/null  # safe: no-op if systemctl unavailable
		return 0
	fi

	# SysV: determine init.d directory
	local init_dir="/etc/init.d"
	if [[ -d /etc/rc.d/init.d ]]; then
		init_dir="/etc/rc.d/init.d"
	fi
	command cp -f "$source_file" "${init_dir}/${name}" || {
		pkg_error "pkg_service_install: failed to copy init script to ${init_dir}"
		return 1
	}
	chmod 755 "${init_dir}/${name}"

	return 0
}

# pkg_service_uninstall name — exhaustive removal from ALL locations
# Arguments:
#   $1 — service name
# Removes unit files, init scripts, chkconfig entries, update-rc.d entries,
# rc-update entries, Slackware S-links, and rc.local entries.
# Returns 0 always (best-effort cleanup).
pkg_service_uninstall() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_uninstall: name required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	# 1. systemd: stop + disable + remove unit files + daemon-reload
	if command -v systemctl >/dev/null 2>&1; then
		systemctl stop "$name" 2>/dev/null     # safe: ignore if not running
		systemctl disable "$name" 2>/dev/null   # safe: ignore if not enabled
	fi

	command rm -f "/usr/lib/systemd/system/${name}.service" 2>/dev/null  # safe: may not exist
	command rm -f "/lib/systemd/system/${name}.service" 2>/dev/null      # safe: may not exist
	command rm -f "/usr/lib/systemd/system/${name}.timer" 2>/dev/null    # safe: timer variant
	command rm -f "/lib/systemd/system/${name}.timer" 2>/dev/null        # safe: timer variant

	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload 2>/dev/null  # safe: refresh after removal
	fi

	# 2. SysV: stop via init script if exists
	local init_script
	if init_script=$(_pkg_init_script_path "$name"); then
		"$init_script" stop 2>/dev/null  # safe: ignore if already stopped
	fi

	# 3. chkconfig: permanent removal
	if command -v chkconfig >/dev/null 2>&1; then
		chkconfig --del "$name" 2>/dev/null  # safe: ignore if not registered
	fi

	# 4. update-rc.d: remove
	if command -v update-rc.d >/dev/null 2>&1; then
		update-rc.d -f "$name" remove 2>/dev/null  # safe: ignore if not registered
	fi

	# 5. rc-update: remove (Gentoo)
	if command -v rc-update >/dev/null 2>&1; then
		rc-update del "$name" default 2>/dev/null  # safe: ignore if not registered
	fi

	# 6. Remove init scripts from both possible locations
	command rm -f "/etc/init.d/${name}" 2>/dev/null          # safe: may not exist
	command rm -f "/etc/rc.d/init.d/${name}" 2>/dev/null     # safe: may not exist

	# 7. Slackware S-links
	local rl rc_dir
	for rl in 2 3 4 5; do
		rc_dir="/etc/rc.d/rc${rl}.d"
		if [[ -d "$rc_dir" ]]; then
			command rm -f "${rc_dir}/"S*"${name}" 2>/dev/null  # safe: glob may match nothing
		fi
	done

	# 8. rc.local cleanup
	pkg_rclocal_remove "$name"

	return 0
}

# pkg_service_install_timer name source_file — install systemd timer unit
# Arguments:
#   $1 — timer name (without .timer suffix)
#   $2 — source timer file path
# Returns 1 if not systemd or on failure.
pkg_service_install_timer() {
	local name="$1" source_file="$2"

	if [[ -z "$name" ]] || [[ -z "$source_file" ]]; then
		pkg_error "pkg_service_install_timer: name and source_file required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	pkg_detect_init

	if [[ "$_PKG_INIT_SYSTEM" != "systemd" ]]; then
		pkg_warn "pkg_service_install_timer: timers require systemd (detected: ${_PKG_INIT_SYSTEM})"
		return 1
	fi

	if [[ ! -f "$source_file" ]]; then
		pkg_error "pkg_service_install_timer: source file not found: ${source_file}"
		return 1
	fi

	local unit_dir
	if ! unit_dir=$(_pkg_systemd_unit_dir); then
		pkg_error "pkg_service_install_timer: cannot locate systemd unit directory"
		return 1
	fi

	local basename_file
	basename_file=$(basename "$source_file")
	command cp -f "$source_file" "${unit_dir}/${basename_file}" || {
		pkg_error "pkg_service_install_timer: failed to copy timer to ${unit_dir}"
		return 1
	}
	systemctl daemon-reload 2>/dev/null  # safe: refresh unit cache

	return 0
}

# pkg_service_install_multi name source_files... — install multiple related units
# Arguments:
#   $1 — service name (for logging)
#   $2+ — source file paths (service, timer, path units, etc.)
# Installs each file via pkg_service_install or pkg_service_install_timer
# based on file extension. Returns 1 if any install fails.
pkg_service_install_multi() {
	local name="$1"
	shift

	if [[ -z "$name" ]] || [[ $# -eq 0 ]]; then
		pkg_error "pkg_service_install_multi: name and at least one source file required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	local source_file rc=0
	local timer_pat='\.timer$'
	for source_file in "$@"; do
		if [[ "$source_file" =~ $timer_pat ]]; then
			pkg_service_install_timer "$name" "$source_file" || rc=1
		else
			pkg_service_install "$name" "$source_file" || rc=1
		fi
	done

	return "$rc"
}

# pkg_service_uninstall_multi name suffixes... — uninstall multiple related units
# Arguments:
#   $1 — service name
#   $2+ — unit suffixes to remove (e.g., ".service" ".timer" ".path")
# Removes each unit file from all systemd unit dirs and runs daemon-reload once.
# Returns 0 always (best-effort cleanup).
pkg_service_uninstall_multi() {
	local name="$1"
	shift

	if [[ -z "$name" ]] || [[ $# -eq 0 ]]; then
		pkg_error "pkg_service_uninstall_multi: name and at least one suffix required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	local suffix
	for suffix in "$@"; do
		# Stop + disable each unit if systemctl available
		if command -v systemctl >/dev/null 2>&1; then
			systemctl stop "${name}${suffix}" 2>/dev/null    # safe: may not be running
			systemctl disable "${name}${suffix}" 2>/dev/null  # safe: may not be enabled
		fi
		# Remove from both possible systemd dirs
		command rm -f "/usr/lib/systemd/system/${name}${suffix}" 2>/dev/null  # safe: may not exist
		command rm -f "/lib/systemd/system/${name}${suffix}" 2>/dev/null      # safe: may not exist
	done

	# Single daemon-reload after all removals
	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload 2>/dev/null  # safe: refresh after bulk removal
	fi

	return 0
}

# --- Service control ---

# pkg_service_start name — start service now
# Arguments:
#   $1 — service name
pkg_service_start() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_start: name required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	_pkg_service_ctl "start" "$name"
}

# pkg_service_stop name — stop service now
# Arguments:
#   $1 — service name
pkg_service_stop() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_stop: name required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	_pkg_service_ctl "stop" "$name"
}

# pkg_service_restart name — restart service now
# Arguments:
#   $1 — service name
pkg_service_restart() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_restart: name required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	_pkg_service_ctl "restart" "$name"
}

# pkg_service_status name — check if service is running
# Arguments:
#   $1 — service name
# Returns 0 if running, 1 if stopped or unknown.
pkg_service_status() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_status: name required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	# systemd path
	if command -v systemctl >/dev/null 2>&1; then
		systemctl is-active --quiet "$name" 2>/dev/null  # returns 0=active, non-zero=inactive
		return $?
	fi

	# SysV path
	local init_script
	if init_script=$(_pkg_init_script_path "$name"); then
		"$init_script" status >/dev/null 2>&1
		return $?
	fi

	return 1
}

# --- Service configuration ---

# pkg_service_enable name — enable service at boot
# Arguments:
#   $1 — service name
# Cascade: systemd → chkconfig (RHEL) → update-rc.d (Debian) →
#   rc-update (Gentoo) → Slackware S-links → unsupported
# Returns 1 on failure.
pkg_service_enable() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_enable: name required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	pkg_detect_init

	# 1. systemd
	if [[ "$_PKG_INIT_SYSTEM" = "systemd" ]]; then
		systemctl enable "$name" 2>/dev/null  # may fail if unit missing
		return $?
	fi

	# OS-family cascades for SysV
	# 2. RHEL: chkconfig
	if [[ "$_PKG_OS_FAMILY" = "rhel" ]]; then
		if command -v chkconfig >/dev/null 2>&1; then
			chkconfig --add "$name" 2>/dev/null  # safe: may already exist
			chkconfig --level "$PKG_CHKCONFIG_LEVELS" "$name" on
			return $?
		fi
	fi

	# 3. Debian: update-rc.d
	if [[ "$_PKG_OS_FAMILY" = "debian" ]]; then
		if command -v update-rc.d >/dev/null 2>&1; then
			update-rc.d "$name" defaults "$PKG_UPDATERCD_START" "$PKG_UPDATERCD_STOP"
			return $?
		fi
	fi

	# 4. Gentoo: rc-update
	if [[ "$_PKG_OS_FAMILY" = "gentoo" ]]; then
		if command -v rc-update >/dev/null 2>&1; then
			rc-update add "$name" default
			return $?
		fi
	fi

	# 5. Slackware: manual S-links
	if [[ "$_PKG_OS_FAMILY" = "slackware" ]]; then
		local init_script
		if init_script=$(_pkg_init_script_path "$name"); then
			local rl rc_dir
			for rl in $PKG_SLACKWARE_RUNLEVELS; do
				rc_dir="/etc/rc.d/rc${rl}.d"
				if [[ -d "$rc_dir" ]]; then
					ln -sf "$init_script" "${rc_dir}/S${PKG_SLACKWARE_PRIORITY}${name}"
				fi
			done
			return 0
		fi
		pkg_error "pkg_service_enable: no init script found for Slackware S-links"
		return 1
	fi

	# 6. Unsupported
	pkg_warn "pkg_service_enable: unsupported init system for enable: ${_PKG_INIT_SYSTEM}"
	return 1
}

# pkg_service_disable name — disable service at boot (reversible)
# Arguments:
#   $1 — service name
# Cascade: systemd → chkconfig off (RHEL) → update-rc.d disable (Debian) →
#   rc-update del (Gentoo) → remove Slackware S-links → unsupported
# Does NOT remove init scripts (use pkg_service_uninstall for that).
# Returns 1 on failure.
pkg_service_disable() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_disable: name required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	pkg_detect_init

	# 1. systemd
	if [[ "$_PKG_INIT_SYSTEM" = "systemd" ]]; then
		systemctl disable "$name" 2>/dev/null  # may fail if unit missing
		return $?
	fi

	# OS-family cascades for SysV
	# 2. RHEL: chkconfig off (reversible — not --del)
	if [[ "$_PKG_OS_FAMILY" = "rhel" ]]; then
		if command -v chkconfig >/dev/null 2>&1; then
			chkconfig "$name" off
			return $?
		fi
	fi

	# 3. Debian: update-rc.d disable
	if [[ "$_PKG_OS_FAMILY" = "debian" ]]; then
		if command -v update-rc.d >/dev/null 2>&1; then
			update-rc.d "$name" disable
			return $?
		fi
	fi

	# 4. Gentoo: rc-update del
	if [[ "$_PKG_OS_FAMILY" = "gentoo" ]]; then
		if command -v rc-update >/dev/null 2>&1; then
			rc-update del "$name" default
			return $?
		fi
	fi

	# 5. Slackware: remove S-links from rc.d directories
	if [[ "$_PKG_OS_FAMILY" = "slackware" ]]; then
		local rl rc_dir
		for rl in $PKG_SLACKWARE_RUNLEVELS; do
			rc_dir="/etc/rc.d/rc${rl}.d"
			if [[ -d "$rc_dir" ]]; then
				command rm -f "${rc_dir}/"S*"${name}" 2>/dev/null  # safe: glob may match nothing
			fi
		done
		return 0
	fi

	# 6. Unsupported
	pkg_warn "pkg_service_disable: unsupported init system for disable: ${_PKG_INIT_SYSTEM}"
	return 1
}

# pkg_service_exists name — check if unit file or init script is installed
# Arguments:
#   $1 — service name
# Returns 0 if found, 1 if not.
pkg_service_exists() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_exists: name required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	# Check systemd unit dir
	local unit_dir
	if unit_dir=$(_pkg_systemd_unit_dir); then
		if [[ -f "${unit_dir}/${name}.service" ]] || [[ -f "${unit_dir}/${name}.timer" ]]; then
			return 0
		fi
	fi

	# Check both systemd dirs explicitly (in case auto-detect picked only one)
	if [[ -f "/usr/lib/systemd/system/${name}.service" ]] || \
	   [[ -f "/lib/systemd/system/${name}.service" ]]; then
		return 0
	fi

	# Check SysV init script
	if _pkg_init_script_path "$name" >/dev/null 2>&1; then
		return 0
	fi

	return 1
}

# pkg_service_is_enabled name — check if service is enabled at boot
# Arguments:
#   $1 — service name
# Returns 0 if enabled, 1 if not.
pkg_service_is_enabled() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_is_enabled: name required"
		return 1
	fi

	# FreeBSD guard
	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	pkg_detect_init

	# systemd
	if [[ "$_PKG_INIT_SYSTEM" = "systemd" ]]; then
		if command -v systemctl >/dev/null 2>&1; then
			systemctl is-enabled --quiet "$name" 2>/dev/null
			return $?
		fi
		return 1
	fi

	# RHEL: chkconfig
	if [[ "$_PKG_OS_FAMILY" = "rhel" ]]; then
		if command -v chkconfig >/dev/null 2>&1; then
			chkconfig "$name" 2>/dev/null  # returns 0 if on
			return $?
		fi
	fi

	# Debian: check for S-links in default runlevel dirs
	if [[ "$_PKG_OS_FAMILY" = "debian" ]]; then
		local rl rc_dir
		for rl in 2 3 4 5; do
			rc_dir="/etc/rc${rl}.d"
			if [[ -d "$rc_dir" ]]; then
				# shellcheck disable=SC2144 # we want any match
				if ls "${rc_dir}/"S*"${name}" >/dev/null 2>&1; then
					return 0
				fi
			fi
		done
		return 1
	fi

	# Gentoo: rc-update show
	if [[ "$_PKG_OS_FAMILY" = "gentoo" ]]; then
		if command -v rc-update >/dev/null 2>&1; then
			rc-update show default 2>/dev/null | grep -q "$name"
			return $?
		fi
	fi

	# Slackware: check for S-links
	if [[ "$_PKG_OS_FAMILY" = "slackware" ]]; then
		local rl rc_dir
		for rl in $PKG_SLACKWARE_RUNLEVELS; do
			rc_dir="/etc/rc.d/rc${rl}.d"
			if [[ -d "$rc_dir" ]]; then
				# shellcheck disable=SC2144 # we want any match
				if ls "${rc_dir}/"S*"${name}" >/dev/null 2>&1; then
					return 0
				fi
			fi
		done
		return 1
	fi

	return 1
}

# --- rc.local management ---

# pkg_rclocal_add entry — add line to rc.local (idempotent)
# Arguments:
#   $1 — line to add to rc.local
# Creates rc.local with #!/bin/bash header and chmod 755 if missing.
# Checks all paths in _PKG_RCLOCAL_PATHS; adds to first existing (or creates first).
# Returns 1 on failure.
pkg_rclocal_add() {
	local entry="$1"

	if [[ -z "$entry" ]]; then
		pkg_error "pkg_rclocal_add: entry required"
		return 1
	fi

	# Find first existing rc.local, or use first path in list
	local rclocal="" path first_path=""
	for path in $_PKG_RCLOCAL_PATHS; do
		if [[ -z "$first_path" ]]; then
			first_path="$path"
		fi
		if [[ -f "$path" ]]; then
			rclocal="$path"
			break
		fi
	done

	# No existing file found — create at first path
	if [[ -z "$rclocal" ]]; then
		rclocal="$first_path"
		if [[ -z "$rclocal" ]]; then
			pkg_error "pkg_rclocal_add: no rc.local paths configured"
			return 1
		fi
		# Ensure parent directory exists
		local rclocal_dir
		rclocal_dir=$(dirname "$rclocal")
		if [[ ! -d "$rclocal_dir" ]]; then
			mkdir -p "$rclocal_dir" || {
				pkg_error "pkg_rclocal_add: failed to create directory ${rclocal_dir}"
				return 1
			}
		fi
		printf '#!/bin/bash\n' > "$rclocal" || {
			pkg_error "pkg_rclocal_add: failed to create ${rclocal}"
			return 1
		}
		chmod 755 "$rclocal"
	fi

	# Idempotency: check if entry already present
	if grep -qF "$entry" "$rclocal" 2>/dev/null; then
		return 0
	fi

	# Append entry
	printf '%s\n' "$entry" >> "$rclocal" || {
		pkg_error "pkg_rclocal_add: failed to append to ${rclocal}"
		return 1
	}

	return 0
}

# pkg_rclocal_remove pattern — remove matching lines from rc.local
# Arguments:
#   $1 — grep pattern to match lines for removal
# Uses grep -v + atomic replace (mktemp + mv) across all rc.local paths.
# Returns 0 always (best-effort cleanup).
pkg_rclocal_remove() {
	local pattern="$1"

	if [[ -z "$pattern" ]]; then
		pkg_error "pkg_rclocal_remove: pattern required"
		return 1
	fi

	local path
	for path in $_PKG_RCLOCAL_PATHS; do
		if [[ ! -f "$path" ]]; then
			continue
		fi

		# Check if pattern exists before modifying (fixed-string match)
		if ! grep -qF "$pattern" "$path" 2>/dev/null; then
			continue
		fi

		# Preserve original permissions before atomic replace
		local _orig_mode
		_orig_mode=$(command stat -Lc '%a' "$path" 2>/dev/null) || \
			_orig_mode=$(command stat -Lf '%OLp' "$path" 2>/dev/null) || \
			_orig_mode="755"

		# Atomic replace: grep -v to tmpfile, then mv
		local tmpfile
		tmpfile=$(mktemp "${PKG_TMPDIR}/rclocal.XXXXXXXXXX") || {
			pkg_warn "pkg_rclocal_remove: mktemp failed for ${path}"
			continue
		}
		grep -vF "$pattern" "$path" > "$tmpfile" 2>/dev/null || true  # safe: grep -v returns 1 when all lines match
		command mv -f "$tmpfile" "$path" || {
			pkg_warn "pkg_rclocal_remove: failed to update ${path}"
			command rm -f "$tmpfile"
			continue
		}

		# Restore original permissions (mktemp creates 0600; rc.local needs 755)
		command chmod "$_orig_mode" "$path" || \
			pkg_warn "pkg_rclocal_remove: failed to restore permissions on ${path}"
	done

	return 0
}

# ══════════════════════════════════════════════════════════════════
# Section: Cron Management
# ══════════════════════════════════════════════════════════════════

# pkg_cron_install src dest [mode] — install cron file with correct permissions
# Arguments:
#   $1 — source file path
#   $2 — destination path (e.g., /etc/cron.d/myapp or /etc/cron.daily/myapp)
#   $3 — optional mode (default: auto-detect from dest path —
#         644 for cron.d, 755 for cron.daily/hourly/weekly/monthly)
# Creates destination directory if missing.
# Returns 1 on failure.
pkg_cron_install() {
	local src="$1" dest="$2" mode="${3:-}"

	if [[ -z "$src" ]] || [[ -z "$dest" ]]; then
		pkg_error "pkg_cron_install: src and dest required"
		return 1
	fi

	if [[ ! -f "$src" ]]; then
		pkg_error "pkg_cron_install: source file not found: ${src}"
		return 1
	fi

	# Auto-detect mode from destination path if not specified
	if [[ -z "$mode" ]]; then
		local cron_exec_pat='cron\.(daily|hourly|weekly|monthly)'
		if [[ "$dest" =~ $cron_exec_pat ]]; then
			mode="755"
		else
			mode="644"
		fi
	fi

	# Ensure destination directory exists
	local dest_dir
	dest_dir=$(dirname "$dest")
	if [[ ! -d "$dest_dir" ]]; then
		mkdir -p "$dest_dir" || {
			pkg_error "pkg_cron_install: failed to create directory ${dest_dir}"
			return 1
		}
	fi

	command cp -f "$src" "$dest" || {
		pkg_error "pkg_cron_install: failed to copy ${src} to ${dest}"
		return 1
	}

	chmod "$mode" "$dest" || {
		pkg_warn "pkg_cron_install: failed to set mode ${mode} on ${dest}"
	}

	pkg_info "installed cron file: ${dest}"
	return 0
}

# pkg_cron_remove paths... — remove cron files
# Arguments:
#   $1+ — cron file paths to remove
# Best-effort removal; warns on failure.
# Returns 0 always.
pkg_cron_remove() {
	if [[ $# -eq 0 ]]; then
		pkg_error "pkg_cron_remove: at least one path required"
		return 1
	fi

	local path
	for path in "$@"; do
		if [[ -f "$path" ]]; then
			command rm -f "$path" || pkg_warn "pkg_cron_remove: failed to remove ${path}"
		fi
	done

	return 0
}

# pkg_cron_cleanup_legacy patterns... — remove old/legacy cron files by path patterns
# Arguments:
#   $1+ — glob patterns to match legacy cron files (e.g., "/etc/cron.d/old_*")
# Each argument is expanded as a glob. Matching files are removed.
# Returns 0 always (best-effort cleanup).
pkg_cron_cleanup_legacy() {
	if [[ $# -eq 0 ]]; then
		pkg_error "pkg_cron_cleanup_legacy: at least one pattern required"
		return 1
	fi

	local pattern path
	for pattern in "$@"; do
		# Expand glob — no-op if pattern matches nothing
		for path in $pattern; do
			if [[ -f "$path" ]]; then
				command rm -f "$path" || pkg_warn "pkg_cron_cleanup_legacy: failed to remove ${path}"
			fi
		done
	done

	return 0
}

# _pkg_cron_read_schedule cron_file — echo the 5-field schedule from first cron line
# Internal helper: reads cron_file, skips comments, empty lines, and variable
# assignments, extracts the first 5 whitespace-delimited fields (cron schedule).
# Echoes the schedule string; returns 1 if no schedule found.
_pkg_cron_read_schedule() {
	local cron_file="$1"
	local line schedule=""
	local comment_pat='^[[:space:]]*(#|$)'
	local assign_pat='^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*='

	while IFS= read -r line; do
		# Skip comments and empty lines
		if [[ "$line" =~ $comment_pat ]]; then
			continue
		fi
		# Skip variable assignments (VAR=value)
		if [[ "$line" =~ $assign_pat ]]; then
			continue
		fi
		# Extract first 5 whitespace-delimited fields (cron schedule)
		schedule=$(echo "$line" | awk '{print $1, $2, $3, $4, $5}')
		if [[ -n "$schedule" ]]; then
			break
		fi
	done < "$cron_file"

	if [[ -z "$schedule" ]]; then
		return 1
	fi

	echo "$schedule"
	return 0
}

# pkg_cron_preserve_schedule cron_file var_name — capture existing schedule
# Arguments:
#   $1 — cron file path
#   $2 — variable name to store the schedule line
# Reads the first non-comment, non-empty line from cron_file and extracts
# the first 5 fields (schedule). Exports the result in the named variable.
# Returns 1 if cron_file not found or no schedule found.
pkg_cron_preserve_schedule() {
	local cron_file="$1" var_name="$2"

	if [[ -z "$cron_file" ]] || [[ -z "$var_name" ]]; then
		pkg_error "pkg_cron_preserve_schedule: cron_file and var_name required"
		return 1
	fi

	if [[ ! -f "$cron_file" ]]; then
		return 1
	fi

	# Validate var_name is a safe shell identifier before eval
	local valid_ident='^[A-Za-z_][A-Za-z0-9_]*$'
	if ! [[ "$var_name" =~ $valid_ident ]]; then
		pkg_error "pkg_cron_preserve_schedule: invalid variable name: ${var_name}"
		return 1
	fi

	local schedule
	schedule=$(_pkg_cron_read_schedule "$cron_file") || return 1

	# Export via eval — var_name validated as safe identifier above
	eval "${var_name}=\${schedule}"
	return 0
}

# pkg_cron_restore_schedule cron_file old_schedule — restore captured schedule
# Arguments:
#   $1 — cron file path
#   $2 — old schedule string (5 cron fields, e.g., "*/10 * * * *")
# Replaces the schedule portion (first 5 fields) of the first non-comment,
# non-assignment line in cron_file with old_schedule.
# Handles sed escaping for * characters in cron expressions.
# Returns 1 if cron_file not found or no cron line found to replace.
pkg_cron_restore_schedule() {
	local cron_file="$1" old_schedule="$2"

	if [[ -z "$cron_file" ]] || [[ -z "$old_schedule" ]]; then
		pkg_error "pkg_cron_restore_schedule: cron_file and old_schedule required"
		return 1
	fi

	if [[ ! -f "$cron_file" ]]; then
		pkg_error "pkg_cron_restore_schedule: file not found: ${cron_file}"
		return 1
	fi

	# Find current schedule from first cron line
	local current_schedule
	current_schedule=$(_pkg_cron_read_schedule "$cron_file") || {
		pkg_warn "pkg_cron_restore_schedule: no cron line found in ${cron_file}"
		return 1
	}

	# If schedules are the same, nothing to do
	if [[ "$current_schedule" = "$old_schedule" ]]; then
		return 0
	fi

	# Escape current_schedule for BRE search: .*[\^$/\ must be escaped
	# Escape old_schedule for sed replacement: &/\ only
	local esc_current esc_old
	esc_current=$(printf '%s' "$current_schedule" | sed 's/[.*[\^$/\\]/\\&/g')
	esc_old=$(printf '%s' "$old_schedule" | sed 's/[&/\\]/\\&/g')

	# Replace first occurrence only (sed with address range)
	sed -i "0,/${esc_current}/s/${esc_current}/${esc_old}/" "$cron_file" || {
		pkg_warn "pkg_cron_restore_schedule: sed replacement failed on ${cron_file}"
		return 1
	}

	return 0
}

# ══════════════════════════════════════════════════════════════════
# Section: Documentation Installation
# ══════════════════════════════════════════════════════════════════

# _pkg_man_dir section — resolve man page directory for given section
# Arguments:
#   $1 — man section number (e.g., "1", "8")
# Priority: /usr/share/man/man$section → /usr/local/share/man/man$section
# Returns 1 if no directory found (creates /usr/share/man/man$section as fallback).
_pkg_man_dir() {
	local section="$1"

	if [[ -d "/usr/share/man/man${section}" ]]; then
		echo "/usr/share/man/man${section}"
		return 0
	fi

	if [[ -d "/usr/local/share/man/man${section}" ]]; then
		echo "/usr/local/share/man/man${section}"
		return 0
	fi

	# Fallback: create standard path
	local fallback="/usr/share/man/man${section}"
	mkdir -p "$fallback" || {
		pkg_error "_pkg_man_dir: failed to create ${fallback}"
		return 1
	}
	echo "$fallback"
	return 0
}

# pkg_man_install src section name [sed_pairs...] — install man page
# Arguments:
#   $1 — source man page file
#   $2 — man section number (e.g., "1", "8")
#   $3 — man page name (without section suffix, e.g., "myapp")
#   $4+ — optional sed replacement pairs as "old|new" strings
# Copies source to temp, applies optional sed replacements, gzip -f,
# installs to man directory as name.section.gz.
# Returns 1 on failure.
pkg_man_install() {
	local src="$1" section="$2" name="$3"
	shift 3

	if [[ -z "$src" ]] || [[ -z "$section" ]] || [[ -z "$name" ]]; then
		pkg_error "pkg_man_install: src, section, and name required"
		return 1
	fi

	if [[ ! -f "$src" ]]; then
		pkg_error "pkg_man_install: source file not found: ${src}"
		return 1
	fi

	local man_dir
	if ! man_dir=$(_pkg_man_dir "$section"); then
		pkg_error "pkg_man_install: cannot resolve man directory for section ${section}"
		return 1
	fi

	# Work on a temp copy for sed + gzip
	local tmpfile
	tmpfile=$(mktemp "${PKG_TMPDIR}/man.XXXXXXXXXX") || {
		pkg_error "pkg_man_install: mktemp failed"
		return 1
	}

	command cp -f "$src" "$tmpfile" || {
		pkg_error "pkg_man_install: failed to copy source to temp"
		command rm -f "$tmpfile"
		return 1
	}

	# Apply optional sed replacement pairs (format: "old|new")
	local pair old_str new_str esc_old esc_new
	for pair in "$@"; do
		old_str="${pair%%|*}"
		new_str="${pair#*|}"
		if [[ -n "$old_str" ]]; then
			# Escape old_str for BRE search: .*[\^$&|/\ must be escaped
			# Escape new_str for sed replacement: &|/\ only
			esc_old=$(printf '%s' "$old_str" | sed 's/[.*[\^$&|/\\]/\\&/g')
			esc_new=$(printf '%s' "$new_str" | sed 's/[&|/\\]/\\&/g')
			sed -i "s|${esc_old}|${esc_new}|g" "$tmpfile" || {
				pkg_warn "pkg_man_install: sed replacement failed for pair: ${pair}"
			}
		fi
	done

	# Compress
	gzip -f "$tmpfile" || {
		pkg_error "pkg_man_install: gzip failed"
		command rm -f "$tmpfile"
		return 1
	}

	# Install to man dir
	local dest="${man_dir}/${name}.${section}.gz"
	command cp -f "${tmpfile}.gz" "$dest" || {
		pkg_error "pkg_man_install: failed to install to ${dest}"
		command rm -f "${tmpfile}.gz"
		return 1
	}
	chmod 644 "$dest"
	command rm -f "${tmpfile}.gz"

	pkg_info "installed man page: ${name}(${section})"
	return 0
}

# _pkg_install_sysfile src name dest_dir func_name — shared sysfile install helper
# Internal helper: validates source file, ensures dest_dir exists, copies with mode 644.
# Arguments:
#   $1 — source file path
#   $2 — name for installed file
#   $3 — destination directory
#   $4 — calling function name (for error messages)
# Returns 1 on failure.
_pkg_install_sysfile() {
	local src="$1" name="$2" dest_dir="$3" func_name="$4"

	if [[ -z "$src" ]] || [[ -z "$name" ]]; then
		pkg_error "${func_name}: src and name required"
		return 1
	fi

	if [[ ! -f "$src" ]]; then
		pkg_error "${func_name}: source file not found: ${src}"
		return 1
	fi

	if [[ ! -d "$dest_dir" ]]; then
		mkdir -p "$dest_dir" || {
			pkg_error "${func_name}: failed to create ${dest_dir}"
			return 1
		}
	fi

	command cp -f "$src" "${dest_dir}/${name}" || {
		pkg_error "${func_name}: failed to install ${name}"
		return 1
	}
	chmod 644 "${dest_dir}/${name}"

	return 0
}

# pkg_bash_completion src name — install bash completion file
# Arguments:
#   $1 — source completion file
#   $2 — name for completion file (e.g., "myapp")
# Installs to /etc/bash_completion.d/ with mode 644.
# Returns 1 on failure.
pkg_bash_completion() {
	_pkg_install_sysfile "$1" "$2" "/etc/bash_completion.d" "pkg_bash_completion" || return 1
	pkg_info "installed bash completion: ${2}"
	return 0
}

# pkg_logrotate_install src name — install logrotate configuration
# Arguments:
#   $1 — source logrotate config file
#   $2 — name for logrotate config (e.g., "myapp")
# Installs to /etc/logrotate.d/ with mode 644.
# Returns 1 on failure.
pkg_logrotate_install() {
	_pkg_install_sysfile "$1" "$2" "/etc/logrotate.d" "pkg_logrotate_install" || return 1
	pkg_info "installed logrotate config: ${2}"
	return 0
}

# pkg_doc_install dest_dir files... — install documentation files
# Arguments:
#   $1 — destination directory (e.g., /usr/share/doc/myapp)
#   $2+ — source files to install (README, CHANGELOG, LICENSE, etc.)
# Creates dest_dir if missing. Copies each file preserving name.
# Returns 1 if dest_dir creation fails or no files specified.
pkg_doc_install() {
	local dest_dir="$1"
	shift

	if [[ -z "$dest_dir" ]] || [[ $# -eq 0 ]]; then
		pkg_error "pkg_doc_install: dest_dir and at least one file required"
		return 1
	fi

	if [[ ! -d "$dest_dir" ]]; then
		mkdir -p "$dest_dir" || {
			pkg_error "pkg_doc_install: failed to create ${dest_dir}"
			return 1
		}
	fi

	local file rc=0
	for file in "$@"; do
		if [[ ! -f "$file" ]]; then
			pkg_warn "pkg_doc_install: file not found, skipping: ${file}"
			continue
		fi
		local basename_file
		basename_file=$(basename "$file")
		command cp -f "$file" "${dest_dir}/${basename_file}" || {
			pkg_warn "pkg_doc_install: failed to copy ${basename_file}"
			rc=1
		}
	done

	return "$rc"
}

# ══════════════════════════════════════════════════════════════════
# Section: Config Migration
# ══════════════════════════════════════════════════════════════════

# pkg_config_get conf_file var — read variable value from config file
# Arguments:
#   $1 — config file path
#   $2 — variable name to read
# Reads the first VAR=value or VAR="value" line matching var.
# Strips surrounding quotes. Echoes raw file bytes to stdout (no shell
# interpretation — escape sequences like \" and \$ are returned literally).
# For the shell-interpreted value, source the file instead.
# Returns 1 if file not found or variable not found.
pkg_config_get() {
	local conf_file="$1" var="$2"

	if [[ -z "$conf_file" ]] || [[ -z "$var" ]]; then
		pkg_error "pkg_config_get: conf_file and var required"
		return 1
	fi

	if [[ ! -f "$conf_file" ]]; then
		pkg_error "pkg_config_get: file not found: ${conf_file}"
		return 1
	fi

	# Validate var name: must be a safe shell variable name
	local _varname_re='^[a-zA-Z_][a-zA-Z0-9_]*$'
	if [[ ! "$var" =~ $_varname_re ]]; then
		pkg_error "pkg_config_get: invalid variable name: ${var}"
		return 1
	fi

	local value
	# Match VAR=value or VAR="value" or VAR='value'
	# Use awk for single-pass extraction
	value=$(awk -F= -v varname="$var" '
		/^[[:space:]]*#/ { next }
		{
			# Trim leading whitespace from field 1 for comparison
			key = $1
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", key)
			if (key == varname) {
				# Remove leading varname= part, get everything after first =
				sub(/^[^=]*=/, "")
				# Strip surrounding quotes
				gsub(/^[[:space:]]*["'"'"']|["'"'"'][[:space:]]*$/, "")
				print
				exit
			}
		}
	' "$conf_file")

	if [[ -z "$value" ]]; then
		# Check if the variable exists with an empty value
		if grep -q "^[[:space:]]*${var}=" "$conf_file"; then
			echo ""
			return 0
		fi
		return 1
	fi

	echo "$value"
	return 0
}

# pkg_config_set conf_file var val — set variable value in config file
# Arguments:
#   $1 — config file path
#   $2 — variable name
#   $3 — new value
# If variable exists, replaces the value in-place via sed.
# If variable does not exist, appends VAR="value" to end of file.
# Returns 1 if file not found.
pkg_config_set() {
	local conf_file="$1" var="$2" val="$3"

	if [[ -z "$conf_file" ]] || [[ -z "$var" ]]; then
		pkg_error "pkg_config_set: conf_file and var required"
		return 1
	fi

	if [[ ! -f "$conf_file" ]]; then
		pkg_error "pkg_config_set: file not found: ${conf_file}"
		return 1
	fi

	# Validate var name: must be a safe shell variable name to prevent
	# regex/sed injection — config variable names never contain metacharacters
	local _varname_re='^[a-zA-Z_][a-zA-Z0-9_]*$'
	if [[ ! "$var" =~ $_varname_re ]]; then
		pkg_error "pkg_config_set: invalid variable name: ${var}"
		return 1
	fi

	# Shell-escape val for sourcing safety: \, ", $, ` must be escaped inside double quotes
	local _shell_val="${val//\\/\\\\}"
	_shell_val="${_shell_val//\"/\\\"}"
	_shell_val="${_shell_val//\$/\\\$}"
	_shell_val="${_shell_val//\`/\\\`}"

	# Escape shell-safe val for sed replacement (handle &, |, /, \)
	# Pipe must be escaped because the outer sed uses | as delimiter
	local esc_val
	esc_val=$(printf '%s' "$_shell_val" | sed 's/[&|/\]/\\&/g')

	# Check if variable already exists (uncommented)
	if grep -q "^[[:space:]]*${var}=" "$conf_file"; then
		# Replace existing value — match VAR=anything
		sed -i "s|^[[:space:]]*${var}=.*|${var}=\"${esc_val}\"|" "$conf_file" || {
			pkg_error "pkg_config_set: sed failed on ${conf_file}"
			return 1
		}
	else
		# Append new variable
		printf '%s="%s"\n' "$var" "$_shell_val" >> "$conf_file" || {
			pkg_error "pkg_config_set: failed to append to ${conf_file}"
			return 1
		}
	fi

	return 0
}

# pkg_config_merge old_conf new_conf output — AWK-based config merge
# Arguments:
#   $1 — old config file (existing user values)
#   $2 — new config file (new template with defaults)
#   $3 — output file path
# Merge strategy:
#   1. First pass: read all VAR=value from old config into array
#   2. Second pass: for each line in new config, if VAR= matches old key,
#      substitute old value; otherwise keep new default
#   3. Preserves comments, ordering, whitespace from new template
#   4. Safe for quoted values, multi-word values, empty values
# A line is treated as an assignment only when it matches a real shell
# assignment anchor (^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=). Lines containing
# `=` or `==` inside conditional expressions (e.g. `[ "$X" = "1" ]`,
# `[[ "$Y" == "auto" ]]`) are passed through unchanged. Files that assign
# the same variable in multiple branches (e.g. if/else STATE_MATCH=...)
# remain unsafe to merge — the last-seen value collapses both branches.
# Use this function only on flat VAR=value config files.
# Returns 1 on failure.
pkg_config_merge() {
	local old_conf="$1" new_conf="$2" output="$3"

	if [[ -z "$old_conf" ]] || [[ -z "$new_conf" ]] || [[ -z "$output" ]]; then
		pkg_error "pkg_config_merge: old_conf, new_conf, and output required"
		return 1
	fi

	if [[ ! -f "$old_conf" ]]; then
		pkg_error "pkg_config_merge: old config not found: ${old_conf}"
		return 1
	fi

	if [[ ! -f "$new_conf" ]]; then
		pkg_error "pkg_config_merge: new config not found: ${new_conf}"
		return 1
	fi

	# Ensure output directory exists
	local output_dir
	output_dir=$(dirname "$output")
	if [[ ! -d "$output_dir" ]]; then
		mkdir -p "$output_dir" || {
			pkg_error "pkg_config_merge: failed to create output directory ${output_dir}"
			return 1
		}
	fi

	# Preserve permissions of new_conf for output file
	# stat -c is GNU coreutils (all supported Linux targets); FreeBSD uses stat -f '%OLp'
	local _preserve_mode=""
	if [[ -f "$new_conf" ]]; then
		_preserve_mode=$(stat -Lc '%a' "$new_conf" 2>/dev/null) || \
			_preserve_mode=$(stat -Lf '%OLp' "$new_conf" 2>/dev/null) || \
			_preserve_mode=""
	fi

	# AWK two-pass merge: old values into new template
	# Uses FILENAME instead of FNR==NR to handle empty old config correctly
	local _tmp_output
	_tmp_output=$(mktemp "${PKG_TMPDIR}/pkg_merge.XXXXXXXXXX") || {
		pkg_error "pkg_config_merge: mktemp failed"
		return 1
	}

	awk -v oldfile="$old_conf" '
	# Anchored shell assignment: optional leading whitespace, identifier, "="
	# Excludes conditional expressions like `[ "$X" = "1" ]` and
	# `[[ "$Y" == "auto" ]]` which contain `=` but are not assignments.
	function is_assignment(line,    _ws) {
		_ws = "^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*="
		return (line ~ _ws)
	}
	# First file (old config): collect VAR=value pairs
	FILENAME == oldfile {
		# Skip comments, empty lines, and non-assignment shell code
		if ($0 ~ /^[[:space:]]*#/ || $0 ~ /^[[:space:]]*$/) next
		if (!is_assignment($0)) next
		pos = index($0, "=")
		varname = substr($0, 1, pos - 1)
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", varname)
		val = substr($0, pos + 1)
		old[varname] = val
		next
	}
	# Second file (new template): output with old values merged
	{
		# Comments and empty lines pass through unchanged
		if ($0 ~ /^[[:space:]]*#/ || $0 ~ /^[[:space:]]*$/) {
			print
			next
		}
		# Non-assignment shell code (conditionals, function bodies, etc.)
		# passes through verbatim — never reinterpret as VAR=value.
		if (!is_assignment($0)) {
			print
			next
		}
		pos = index($0, "=")
		varname = substr($0, 1, pos - 1)
		gsub(/^[[:space:]]+|[[:space:]]+$/, "", varname)
		if (varname in old) {
			# Substitute old value into new template line
			print varname "=" old[varname]
			next
		}
		# Variable not in old config — keep new template line as-is
		print
	}
	' "$old_conf" "$new_conf" > "$_tmp_output" || {
		pkg_error "pkg_config_merge: awk merge failed"
		command rm -f "$_tmp_output"
		return 1
	}

	command mv -f "$_tmp_output" "$output" || {
		pkg_error "pkg_config_merge: failed to write merged output to ${output}"
		command rm -f "$_tmp_output"
		return 1
	}

	if [[ -n "$_preserve_mode" ]]; then
		chmod "$_preserve_mode" "$output" || pkg_warn "pkg_config_merge: failed to restore permissions on ${output}"
	fi

	return 0
}

# pkg_config_migrate_var conf_file old_var new_var [transform] — rename config variable
# Arguments:
#   $1 — config file path
#   $2 — old variable name
#   $3 — new variable name
#   $4 — optional transform: "none" (default), "lower", "upper"
# If old_var exists and new_var does not, renames old_var to new_var.
# Optionally transforms the value. Leaves a comment noting the migration.
# Returns 0 if migrated or if no migration needed; 1 on error.
pkg_config_migrate_var() {
	local conf_file="$1" old_var="$2" new_var="$3" transform="${4:-none}"

	if [[ -z "$conf_file" ]] || [[ -z "$old_var" ]] || [[ -z "$new_var" ]]; then
		pkg_error "pkg_config_migrate_var: conf_file, old_var, and new_var required"
		return 1
	fi

	if [[ ! -f "$conf_file" ]]; then
		pkg_error "pkg_config_migrate_var: file not found: ${conf_file}"
		return 1
	fi

	# Validate variable names: must be safe shell identifiers
	local _varname_re='^[a-zA-Z_][a-zA-Z0-9_]*$'
	if [[ ! "$old_var" =~ $_varname_re ]]; then
		pkg_error "pkg_config_migrate_var: invalid variable name: ${old_var}"
		return 1
	fi
	if [[ ! "$new_var" =~ $_varname_re ]]; then
		pkg_error "pkg_config_migrate_var: invalid variable name: ${new_var}"
		return 1
	fi

	# Check if old_var exists
	if ! grep -q "^[[:space:]]*${old_var}=" "$conf_file"; then
		# Nothing to migrate
		return 0
	fi

	# Check if new_var already exists
	if grep -q "^[[:space:]]*${new_var}=" "$conf_file"; then
		# New var already set — just comment out old var
		sed -i "s|^[[:space:]]*${old_var}=|# migrated to ${new_var}: ${old_var}=|" "$conf_file"
		return 0
	fi

	# Read old value
	local old_val
	old_val=$(pkg_config_get "$conf_file" "$old_var") || old_val=""

	# Apply transform
	case "$transform" in
		lower)
			old_val=$(echo "$old_val" | tr '[:upper:]' '[:lower:]')
			;;
		upper)
			old_val=$(echo "$old_val" | tr '[:lower:]' '[:upper:]')
			;;
		none|"")
			: # no transform
			;;
		*)
			pkg_warn "pkg_config_migrate_var: unknown transform '${transform}', using none"
			;;
	esac

	# Shell-escape old_val for sourcing safety: the AWK raw reader returns literal
	# file bytes between quotes — single-quoted originals lack escape sequences,
	# so writing them inside double quotes without escaping creates injection vectors.
	# Escape \, ", $, ` for double-quote context (backslash first to avoid double-escaping).
	local _shell_val="${old_val//\\/\\\\}"
	_shell_val="${_shell_val//\"/\\\"}"
	_shell_val="${_shell_val//\$/\\\$}"
	_shell_val="${_shell_val//\`/\\\`}"

	# Escape shell-safe val for sed replacement (handle &, |, /, \)
	local esc_val
	esc_val=$(printf '%s' "$_shell_val" | sed 's/[&|/\]/\\&/g')

	# Replace old_var line with new_var and add migration comment
	sed -i "s|^[[:space:]]*${old_var}=.*|# migrated: ${old_var} -> ${new_var}\n${new_var}=\"${esc_val}\"|" "$conf_file" || {
		pkg_error "pkg_config_migrate_var: sed failed on ${conf_file}"
		return 1
	}

	return 0
}

# pkg_config_clamp conf_file var max_val [msg] — clamp numeric config value
# Arguments:
#   $1 — config file path
#   $2 — variable name
#   $3 — maximum allowed value (integer)
#   $4 — optional warning message (logged if value is clamped)
# If the current value exceeds max_val, sets it to max_val and warns.
# No-op if variable not found or value is within range.
# Returns 0 on success; 1 on error.
pkg_config_clamp() {
	local conf_file="$1" var="$2" max_val="$3" msg="${4:-}"

	if [[ -z "$conf_file" ]] || [[ -z "$var" ]] || [[ -z "$max_val" ]]; then
		pkg_error "pkg_config_clamp: conf_file, var, and max_val required"
		return 1
	fi

	if [[ ! -f "$conf_file" ]]; then
		pkg_error "pkg_config_clamp: file not found: ${conf_file}"
		return 1
	fi

	# Validate max_val is numeric
	local numeric_pat='^[0-9]+$'
	if ! [[ "$max_val" =~ $numeric_pat ]]; then
		pkg_error "pkg_config_clamp: max_val must be a positive integer"
		return 1
	fi

	# Read current value
	local current_val
	current_val=$(pkg_config_get "$conf_file" "$var") || return 0  # not found = no-op

	# Check if current value is numeric
	if ! [[ "$current_val" =~ $numeric_pat ]]; then
		return 0  # non-numeric value — skip clamping
	fi

	# Compare and clamp if needed
	if [[ "$current_val" -gt "$max_val" ]]; then
		pkg_config_set "$conf_file" "$var" "$max_val" || return 1
		if [[ -n "$msg" ]]; then
			pkg_warn "$msg"
		else
			pkg_warn "pkg_config_clamp: ${var} clamped from ${current_val} to ${max_val}"
		fi
	fi

	return 0
}

# ══════════════════════════════════════════════════════════════════
# Section: FHS Layout & Symlink Farm
# ══════════════════════════════════════════════════════════════════

# FHS registry — parallel indexed arrays (NOT declare -A)
# Populated by pkg_fhs_register(), consumed by pkg_fhs_install() and generators.
_PKG_FHS_SRCS=()
_PKG_FHS_DESTS=()
_PKG_FHS_MODES=()
_PKG_FHS_TYPES=()

# pkg_fhs_register src fhs_dest mode [type] — register a file mapping
# Arguments:
#   $1 — source relative path (e.g., "files/bfd")
#   $2 — FHS destination path (e.g., "/usr/sbin/bfd")
#   $3 — permission mode (e.g., "750")
#   $4 — optional type: bin|lib|conf|data|state|doc (default: "data")
# Appends to parallel indexed arrays. Returns 1 on validation failure.
pkg_fhs_register() {
	local src="$1" fhs_dest="$2" mode="$3" ftype="${4:-data}"

	if [[ -z "$src" ]] || [[ -z "$fhs_dest" ]] || [[ -z "$mode" ]]; then
		pkg_error "pkg_fhs_register: src, fhs_dest, and mode required"
		return 1
	fi

	# Validate type
	case "$ftype" in
		bin|lib|conf|data|state|doc) ;;
		*)
			pkg_error "pkg_fhs_register: invalid type '${ftype}' (expected bin|lib|conf|data|state|doc)"
			return 1
			;;
	esac

	# Validate mode is numeric (3-4 digit octal)
	local mode_pat='^[0-7]{3,4}$'
	if ! [[ "$mode" =~ $mode_pat ]]; then
		pkg_error "pkg_fhs_register: invalid mode '${mode}' (expected octal, e.g., 750)"
		return 1
	fi

	_PKG_FHS_SRCS+=("$src")
	_PKG_FHS_DESTS+=("$fhs_dest")
	_PKG_FHS_MODES+=("$mode")
	_PKG_FHS_TYPES+=("$ftype")

	return 0
}

# pkg_fhs_install src_dir — install all registered files from source to FHS paths
# Arguments:
#   $1 — source directory root (files are resolved relative to this)
# Copies each registered file from src_dir/src to fhs_dest with the
# specified permission mode. Creates parent directories as needed.
# Returns 1 on any copy failure (continues processing remaining files).
pkg_fhs_install() {
	local src_dir="$1"

	if [[ -z "$src_dir" ]]; then
		pkg_error "pkg_fhs_install: src_dir required"
		return 1
	fi

	if [[ ! -d "$src_dir" ]]; then
		pkg_error "pkg_fhs_install: source directory not found: ${src_dir}"
		return 1
	fi

	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		pkg_warn "pkg_fhs_install: no files registered"
		return 0
	fi

	local i rc=0 failed=0 src_path dest_path dest_dir
	for ((i = 0; i < count; i++)); do
		src_path="${src_dir}/${_PKG_FHS_SRCS[$i]}"
		dest_path="${_PKG_FHS_DESTS[$i]}"
		dest_dir="$(dirname "$dest_path")"

		# Create destination directory if needed
		if [[ ! -d "$dest_dir" ]]; then
			mkdir -p "$dest_dir" || {
				pkg_error "pkg_fhs_install: failed to create directory ${dest_dir}"
				rc=1
				failed=$((failed + 1))
				continue
			}
		fi

		# Handle directory-type sources (state dirs, etc.)
		if [[ -d "$src_path" ]]; then
			command cp -pR "$src_path" "$dest_path" || {
				pkg_error "pkg_fhs_install: failed to copy directory ${_PKG_FHS_SRCS[$i]}"
				rc=1
				failed=$((failed + 1))
				continue
			}
		elif [[ -f "$src_path" ]]; then
			command cp -p "$src_path" "$dest_path" || {
				pkg_error "pkg_fhs_install: failed to copy ${_PKG_FHS_SRCS[$i]}"
				rc=1
				failed=$((failed + 1))
				continue
			}
		else
			pkg_warn "pkg_fhs_install: source not found: ${_PKG_FHS_SRCS[$i]}"
			rc=1
			failed=$((failed + 1))
			continue
		fi

		# Set permissions
		chmod "${_PKG_FHS_MODES[$i]}" "$dest_path" 2>/dev/null  # best-effort chmod
	done

	local installed=$((count - failed))
	if [[ "$installed" -gt 0 ]]; then
		pkg_info "installed ${installed} file(s) to FHS layout"
	fi

	return "$rc"
}

# pkg_fhs_symlink_farm legacy_root — create backward-compat symlink farm
# Arguments:
#   $1 — legacy install root (e.g., "/usr/local/bfd")
# Creates symlinks from legacy paths to real FHS locations for each
# registered file. Creates parent directories under legacy_root as needed.
# Allows old scripts and configs pointing to the legacy path to keep working.
# Returns 1 on any symlink failure (continues processing remaining entries).
pkg_fhs_symlink_farm() {
	local legacy_root="$1"

	if [[ -z "$legacy_root" ]]; then
		pkg_error "pkg_fhs_symlink_farm: legacy_root required"
		return 1
	fi

	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		pkg_warn "pkg_fhs_symlink_farm: no files registered"
		return 0
	fi

	local i rc=0 failed=0 legacy_path dest_path link_dir
	for ((i = 0; i < count; i++)); do
		dest_path="${_PKG_FHS_DESTS[$i]}"
		legacy_path="${legacy_root}/${_PKG_FHS_SRCS[$i]}"
		link_dir="$(dirname "$legacy_path")"

		# Create parent directory for the symlink
		if [[ ! -d "$link_dir" ]]; then
			mkdir -p "$link_dir" || {
				pkg_error "pkg_fhs_symlink_farm: failed to create ${link_dir}"
				rc=1
				failed=$((failed + 1))
				continue
			}
		fi

		# Create symlink: legacy_path -> fhs_dest
		pkg_symlink "$dest_path" "$legacy_path" || {
			rc=1
			failed=$((failed + 1))
			continue
		}
	done

	local linked=$((count - failed))
	if [[ "$linked" -gt 0 ]]; then
		pkg_info "created ${linked} backward-compat symlink(s) in ${legacy_root}"
	fi

	return "$rc"
}

# pkg_fhs_symlink_farm_cleanup legacy_root — remove symlink farm
# Arguments:
#   $1 — legacy install root (e.g., "/usr/local/bfd")
# Removes symlinks created by pkg_fhs_symlink_farm(). Skips non-symlinks
# for safety. Removes empty parent directories under legacy_root afterward.
# Returns 0 always (best-effort cleanup).
pkg_fhs_symlink_farm_cleanup() {
	local legacy_root="$1"

	if [[ -z "$legacy_root" ]]; then
		pkg_error "pkg_fhs_symlink_farm_cleanup: legacy_root required"
		return 1
	fi

	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		return 0
	fi

	local i legacy_path
	for ((i = 0; i < count; i++)); do
		legacy_path="${legacy_root}/${_PKG_FHS_SRCS[$i]}"
		if [[ -L "$legacy_path" ]]; then
			command rm -f "$legacy_path"
		fi
	done

	# Clean up empty directories under legacy_root (bottom-up)
	if [[ -d "$legacy_root" ]]; then
		find "$legacy_root" -type d -empty -delete 2>/dev/null  # best-effort cleanup
	fi

	return 0
}

# pkg_fhs_gen_rpm_files — generate RPM %files section from registry
# Outputs RPM %files lines to stdout. Config files get %config(noreplace).
# Directories get %dir. Call after populating registry with pkg_fhs_register().
pkg_fhs_gen_rpm_files() {
	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		return 0
	fi

	# Track directories we have already emitted
	local seen_dirs="" i dest ftype dest_dir

	for ((i = 0; i < count; i++)); do
		dest="${_PKG_FHS_DESTS[$i]}"
		ftype="${_PKG_FHS_TYPES[$i]}"
		dest_dir="$(dirname "$dest")"

		# Emit %dir for parent directory if not seen
		case "$seen_dirs" in
			*"|${dest_dir}|"*) ;;
			*)
				echo "%dir ${dest_dir}"
				seen_dirs="${seen_dirs}|${dest_dir}|"
				;;
		esac

		# Config files get %config(noreplace)
		if [[ "$ftype" = "conf" ]]; then
			echo "%config(noreplace) ${dest}"
		else
			echo "${dest}"
		fi
	done

	return 0
}

# pkg_fhs_gen_deb_dirs — generate DEB dirs file from registry
# Outputs unique directory paths (one per line) to stdout.
pkg_fhs_gen_deb_dirs() {
	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		return 0
	fi

	local seen_dirs="" i dest_dir

	for ((i = 0; i < count; i++)); do
		dest_dir="$(dirname "${_PKG_FHS_DESTS[$i]}")"

		# Emit directory if not seen
		case "$seen_dirs" in
			*"|${dest_dir}|"*) ;;
			*)
				echo "$dest_dir"
				seen_dirs="${seen_dirs}|${dest_dir}|"
				;;
		esac
	done

	return 0
}

# pkg_fhs_gen_deb_links legacy_root — generate DEB links file from registry
# Arguments:
#   $1 — legacy install root (e.g., "/usr/local/bfd")
# Outputs "fhs_dest legacy_path" pairs to stdout (DEB links format).
pkg_fhs_gen_deb_links() {
	local legacy_root="$1"

	if [[ -z "$legacy_root" ]]; then
		pkg_error "pkg_fhs_gen_deb_links: legacy_root required"
		return 1
	fi

	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		return 0
	fi

	local i dest legacy_path
	for ((i = 0; i < count; i++)); do
		dest="${_PKG_FHS_DESTS[$i]}"
		legacy_path="${legacy_root}/${_PKG_FHS_SRCS[$i]}"
		echo "${dest} ${legacy_path}"
	done

	return 0
}

# pkg_fhs_gen_deb_conffiles — generate DEB conffiles from registry (type=conf only)
# Outputs absolute paths of config files to stdout (one per line).
pkg_fhs_gen_deb_conffiles() {
	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		return 0
	fi

	local i
	for ((i = 0; i < count; i++)); do
		if [[ "${_PKG_FHS_TYPES[$i]}" = "conf" ]]; then
			echo "${_PKG_FHS_DESTS[$i]}"
		fi
	done

	return 0
}

# pkg_fhs_gen_sed_pairs install_path_var — generate sed expressions for path transform
# Arguments:
#   $1 — install path variable name (e.g., "INSTALL_PATH" or "inspath")
# Generates sed -e expressions replacing FHS destination directory paths with
# a variable reference. Used by install.sh to patch scripts at install time.
# Example output: -e 's|/usr/sbin|$INSTALL_PATH|g'
pkg_fhs_gen_sed_pairs() {
	local install_path_var="$1"

	if [[ -z "$install_path_var" ]]; then
		pkg_error "pkg_fhs_gen_sed_pairs: install_path_var required"
		return 1
	fi

	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		return 0
	fi

	# Collect unique directory prefixes from destinations
	local seen_prefixes="" i dest_dir

	for ((i = 0; i < count; i++)); do
		dest_dir="$(dirname "${_PKG_FHS_DESTS[$i]}")"

		case "$seen_prefixes" in
			*"|${dest_dir}|"*) ;;
			*)
				echo "-e 's|${dest_dir}|\$${install_path_var}|g'"
				seen_prefixes="${seen_prefixes}|${dest_dir}|"
				;;
		esac
	done

	return 0
}

# pkg_fhs_gen_manifest legacy_root — generate symlink manifest from FHS registry
# Arguments:
#   $1 — legacy install root (e.g., "/etc/apf", "/usr/local/bfd")
# Writes a tab-separated manifest to stdout mapping legacy symlink paths
# to their FHS target paths. Used at package build time to produce a
# manifest file consumed by pkg_fhs_verify_farm() at runtime.
# Output format:
#   # pkg_lib:symlink-manifest:1
#   {legacy_root}/{src}\t{fhs_dest}
pkg_fhs_gen_manifest() {
	local legacy_root="$1"

	if [[ -z "$legacy_root" ]]; then
		pkg_error "pkg_fhs_gen_manifest: legacy_root required"
		return 1
	fi

	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		pkg_warn "pkg_fhs_gen_manifest: no files registered"
		return 0
	fi

	echo "# pkg_lib:symlink-manifest:1"

	local i
	for ((i = 0; i < count; i++)); do
		printf '%s\t%s\n' "${legacy_root}/${_PKG_FHS_SRCS[$i]}" "${_PKG_FHS_DESTS[$i]}"
	done

	return 0
}

# pkg_fhs_verify_farm manifest_path — verify and repair symlink farm from manifest
# Arguments:
#   $1 — path to manifest file (e.g., "$INSTALL_PATH/internals/.symlink-manifest")
# Reads the manifest and verifies each symlink entry. Repairs broken, missing,
# wrong-target, and regular-file-replaced symlinks when the target exists.
# Returns 0 if all symlinks are valid (including after repair).
# Returns 1 if any target is missing or a directory blocks a symlink path.
# Returns 0 silently if the manifest file does not exist (install.sh layout).
pkg_fhs_verify_farm() {
	local manifest_path="$1"

	if [[ -z "$manifest_path" ]]; then
		pkg_error "pkg_fhs_verify_farm: manifest_path required"
		return 1
	fi

	# No manifest = install.sh layout, no symlink farm to verify
	if [[ ! -f "$manifest_path" ]]; then
		return 0
	fi

	local rc=0
	local link_path target

	while IFS=$'\t' read -r link_path target; do
		# Skip blank lines
		[[ -z "$link_path" ]] && continue
		# Skip comment lines
		[[ "$link_path" = \#* ]] && continue
		# Skip malformed lines (no target after tab-split)
		if [[ -z "$target" ]]; then
			pkg_warn "malformed manifest line: ${link_path}"
			continue
		fi

		# State: valid symlink, correct target — skip
		if [[ -L "$link_path" ]]; then
			local current_target
			current_target=$(readlink "$link_path")
			if [[ "$current_target" = "$target" ]]; then
				# Correct — check target still exists
				if [[ -e "$link_path" ]]; then
					continue
				fi
				# Symlink is correct but target is gone (dangling)
				pkg_error "symlink target missing: ${target} — reinstall package"
				rc=1
				continue
			fi

			# State: valid symlink, wrong target
			if [[ -e "$link_path" ]]; then
				# Wrong target but points to something that exists
				pkg_symlink "$target" "$link_path"
				pkg_warn "repaired symlink (wrong target): ${link_path}"
				continue
			fi

			# Broken symlink (dangling) with wrong target — check if correct target exists
			if [[ -e "$target" ]]; then
				pkg_symlink "$target" "$link_path"
				pkg_warn "repaired symlink: ${link_path} -> ${target}"
			else
				pkg_error "symlink target missing: ${target} — reinstall package"
				rc=1
			fi
			continue
		fi

		# State: directory at link path (not a symlink)
		if [[ -d "$link_path" ]]; then
			pkg_error "directory exists at symlink path: ${link_path} — remove manually"
			rc=1
			continue
		fi

		# State: regular file at link path (not a symlink)
		if [[ -e "$link_path" ]]; then
			pkg_symlink "$target" "$link_path"
			pkg_warn "replaced regular file with symlink: ${link_path}"
			continue
		fi

		# State: nothing at link path (missing)
		if [[ -e "$target" ]]; then
			pkg_symlink "$target" "$link_path"
			pkg_warn "repaired symlink: ${link_path} -> ${target}"
		else
			pkg_error "symlink target missing: ${target} — reinstall package"
			rc=1
		fi
	done < "$manifest_path"

	return "$rc"
}

# ══════════════════════════════════════════════════════════════════
# Section: Uninstall Primitives
# ══════════════════════════════════════════════════════════════════

# pkg_uninstall_confirm project_name — interactive y/N confirmation prompt
# Arguments:
#   $1 — project name (e.g., "BFD", "APF")
# Reads from stdin. Returns 0 if confirmed (y/Y), 1 if declined or non-interactive.
pkg_uninstall_confirm() {
	local project_name="$1"

	if [[ -z "$project_name" ]]; then
		pkg_error "pkg_uninstall_confirm: project_name required"
		return 1
	fi

	local answer=""
	echo ""
	read -r -p "  Are you sure you want to uninstall ${project_name}? [y/N] " answer
	echo ""

	case "$answer" in
		y|Y) return 0 ;;
		*)   return 1 ;;
	esac
}

# pkg_uninstall_files paths... — remove files and directories
# Arguments:
#   $1+ — file or directory paths to remove
# Skips paths that do not exist (no error). Removes files with rm -f,
# directories with rm -rf. Returns 0 always (best-effort removal).
pkg_uninstall_files() {
	if [[ $# -eq 0 ]]; then
		pkg_error "pkg_uninstall_files: at least one path required"
		return 1
	fi

	local path
	for path in "$@"; do
		if [[ ! -e "$path" ]] && [[ ! -L "$path" ]]; then
			continue  # skip non-existent paths silently
		fi

		if [[ -d "$path" ]] && [[ ! -L "$path" ]]; then
			command rm -rf "$path" || pkg_warn "pkg_uninstall_files: failed to remove directory ${path}"
		else
			command rm -f "$path" || pkg_warn "pkg_uninstall_files: failed to remove ${path}"
		fi
	done

	return 0
}

# pkg_uninstall_man section name — remove installed man page
# Arguments:
#   $1 — man section number (e.g., "1", "8")
#   $2 — man page name without section (e.g., "maldet", "bfd")
# Removes both uncompressed and gzipped man pages from standard locations.
# Returns 0 always (best-effort removal).
pkg_uninstall_man() {
	local section="$1" name="$2"

	if [[ -z "$section" ]] || [[ -z "$name" ]]; then
		pkg_error "pkg_uninstall_man: section and name required"
		return 1
	fi

	local man_dirs="/usr/share/man /usr/local/share/man /usr/local/man"
	local dir
	for dir in $man_dirs; do
		command rm -f "${dir}/man${section}/${name}.${section}" 2>/dev/null     # uncompressed
		command rm -f "${dir}/man${section}/${name}.${section}.gz" 2>/dev/null  # gzipped
	done

	return 0
}

# pkg_uninstall_cron paths... — remove cron files
# Arguments:
#   $1+ — cron file paths to remove (e.g., "/etc/cron.d/bfd", "/etc/cron.daily/bfd")
# Skips paths that do not exist. Returns 0 always (best-effort removal).
pkg_uninstall_cron() {
	if [[ $# -eq 0 ]]; then
		pkg_error "pkg_uninstall_cron: at least one path required"
		return 1
	fi

	local path
	for path in "$@"; do
		if [[ -f "$path" ]] || [[ -L "$path" ]]; then
			command rm -f "$path" || pkg_warn "pkg_uninstall_cron: failed to remove ${path}"
		fi
	done

	return 0
}

# pkg_uninstall_logrotate name — remove logrotate config
# Arguments:
#   $1 — logrotate config name (e.g., "bfd", "maldet")
# Removes /etc/logrotate.d/$name.
# Returns 0 always (best-effort removal).
pkg_uninstall_logrotate() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_uninstall_logrotate: name required"
		return 1
	fi

	command rm -f "/etc/logrotate.d/${name}" 2>/dev/null  # best-effort removal
	return 0
}

# pkg_uninstall_completion name — remove bash completion file
# Arguments:
#   $1 — completion script name (e.g., "bfd", "maldet")
# Removes /etc/bash_completion.d/$name.
# Returns 0 always (best-effort removal).
pkg_uninstall_completion() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_uninstall_completion: name required"
		return 1
	fi

	command rm -f "/etc/bash_completion.d/${name}" 2>/dev/null  # best-effort removal
	return 0
}

# pkg_uninstall_sysconfig name — remove sysconfig/default override file
# Arguments:
#   $1 — service name (e.g., "bfd", "apf")
# Removes /etc/sysconfig/$name (RHEL) and /etc/default/$name (Debian).
# Returns 0 always (best-effort removal).
pkg_uninstall_sysconfig() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_uninstall_sysconfig: name required"
		return 1
	fi

	command rm -f "/etc/sysconfig/${name}" 2>/dev/null  # RHEL-family
	command rm -f "/etc/default/${name}" 2>/dev/null    # Debian-family
	return 0
}

# ══════════════════════════════════════════════════════════════════
# Section: Manifest Support
# ══════════════════════════════════════════════════════════════════

# pkg_manifest_load manifest_file — source a project manifest file
# Arguments:
#   $1 — path to manifest file (e.g., "pkg.manifest")
# Sources the file to set PKG_* variables. The manifest file is a plain
# bash variable assignment file (key="value" per line).
# Returns 1 if file not found or source fails.
pkg_manifest_load() {
	local manifest_file="$1"

	if [[ -z "$manifest_file" ]]; then
		pkg_error "pkg_manifest_load: manifest_file required"
		return 1
	fi

	if [[ ! -f "$manifest_file" ]]; then
		pkg_error "pkg_manifest_load: file not found: ${manifest_file}"
		return 1
	fi

	# Defense-in-depth: reject manifest not owned by current user
	if [[ ! -O "$manifest_file" ]]; then
		pkg_error "pkg_manifest_load: ${manifest_file} not owned by current user"
		return 1
	fi

	# shellcheck disable=SC1090
	source "$manifest_file" || {
		pkg_error "pkg_manifest_load: failed to source ${manifest_file}"
		return 1
	}

	return 0
}

# pkg_manifest_validate — validate required manifest variables are set
# Checks that PKG_NAME, PKG_VERSION, PKG_SUMMARY, and PKG_INSTALL_PATH
# are non-empty. Returns 1 if any required variable is missing.
pkg_manifest_validate() {
	local rc=0

	if [[ -z "${PKG_NAME:-}" ]]; then
		pkg_error "pkg_manifest_validate: PKG_NAME is required"
		rc=1
	fi

	if [[ -z "${PKG_VERSION:-}" ]]; then
		pkg_error "pkg_manifest_validate: PKG_VERSION is required"
		rc=1
	fi

	if [[ -z "${PKG_SUMMARY:-}" ]]; then
		pkg_error "pkg_manifest_validate: PKG_SUMMARY is required"
		rc=1
	fi

	if [[ -z "${PKG_INSTALL_PATH:-}" ]]; then
		pkg_error "pkg_manifest_validate: PKG_INSTALL_PATH is required"
		rc=1
	fi

	return "$rc"
}
