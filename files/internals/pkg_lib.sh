#!/bin/bash
#
# pkg_lib.sh — Shared Packaging & Installer Library 1.0.10
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
PKG_LIB_VERSION="1.0.10"

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

# _pkg_color_init — detect terminal color support, populate _PKG_C_* vars
# Idempotent; non-terminal or PKG_NO_COLOR=1 → all colors empty.
_pkg_color_init() {
	[[ -n "$_PKG_COLOR_INIT_DONE" ]] && return 0

	_PKG_COLOR_INIT_DONE=1
	_PKG_C_RED=""
	_PKG_C_GREEN=""
	_PKG_C_YELLOW=""
	_PKG_C_BOLD=""
	_PKG_C_RESET=""

	if [[ "${PKG_NO_COLOR:-0}" = "1" ]]; then
		return 0
	fi

	if [[ ! -t 1 ]]; then
		return 0
	fi

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

# pkg_info message — print info message with consistent prefix (suppressed when PKG_QUIET=1)
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

# pkg_item label value — print aligned "label: value" pair
pkg_item() {
	local label="$1" value="$2"
	printf "  %-20s %s\n" "${label}:" "$value"
	return 0
}

# pkg_detect_os — populate _PKG_OS_{FAMILY,ID,VERSION,NAME} from /etc probes
# Detection chain: os-release → redhat-release → debian_version → gentoo-release →
# slackware-version → uname (FreeBSD). Idempotent.
pkg_detect_os() {
	[[ -n "$_PKG_OS_DETECT_DONE" ]] && return 0
	_PKG_OS_DETECT_DONE=1

	_PKG_OS_FAMILY="unknown"
	_PKG_OS_ID="unknown"
	_PKG_OS_VERSION=""
	_PKG_OS_NAME="unknown"

	if [[ -f /etc/os-release ]]; then
		local line key val
		while IFS= read -r line; do
			[[ "$line" =~ ^[[:space:]]*# ]] && continue
			[[ -z "$line" ]] && continue
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
					case "$val" in
						*rhel*|*centos*|*fedora*) _PKG_OS_FAMILY="rhel" ;;
						*debian*)                 _PKG_OS_FAMILY="debian" ;;
					esac
					;;
				PRETTY_NAME) _PKG_OS_NAME="$val" ;;
			esac
		done < /etc/os-release

		if [[ "$_PKG_OS_FAMILY" = "unknown" ]]; then
			case "$_PKG_OS_ID" in
				centos|rhel|rocky|alma|fedora|ol|amzn) _PKG_OS_FAMILY="rhel" ;;
				debian|ubuntu|linuxmint|raspbian)      _PKG_OS_FAMILY="debian" ;;
				gentoo)                                 _PKG_OS_FAMILY="gentoo" ;;
				slackware)                              _PKG_OS_FAMILY="slackware" ;;
			esac
		fi

		if [[ "$_PKG_OS_NAME" = "unknown" ]]; then
			_PKG_OS_NAME="${_PKG_OS_ID} ${_PKG_OS_VERSION}"
		fi
		return 0
	fi

	if [[ -f /etc/redhat-release ]]; then
		_PKG_OS_FAMILY="rhel"
		_PKG_OS_NAME=$(cat /etc/redhat-release 2>/dev/null) || _PKG_OS_NAME="RHEL-family"
		local ver_pat='[0-9]+(\.[0-9]+)*'
		if [[ "$_PKG_OS_NAME" =~ $ver_pat ]]; then
			_PKG_OS_VERSION="${BASH_REMATCH[0]}"
		fi
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

	if [[ -f /etc/debian_version ]]; then
		_PKG_OS_FAMILY="debian"
		_PKG_OS_ID="debian"
		_PKG_OS_VERSION=$(cat /etc/debian_version 2>/dev/null) || _PKG_OS_VERSION=""
		_PKG_OS_NAME="Debian ${_PKG_OS_VERSION}"
		return 0
	fi

	if [[ -f /etc/gentoo-release ]]; then
		_PKG_OS_FAMILY="gentoo"
		_PKG_OS_ID="gentoo"
		_PKG_OS_NAME=$(cat /etc/gentoo-release 2>/dev/null) || _PKG_OS_NAME="Gentoo"
		return 0
	fi

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

# pkg_detect_init — set _PKG_INIT_SYSTEM to systemd|sysv|upstart|rc.local|unknown
# Idempotent; /proc/1/comm check guarded because CentOS 6 may lack it.
pkg_detect_init() {
	[[ -n "$_PKG_INIT_DETECT_DONE" ]] && return 0
	_PKG_INIT_DETECT_DONE=1

	_PKG_INIT_SYSTEM="unknown"

	if [[ -d /run/systemd/system ]]; then
		_PKG_INIT_SYSTEM="systemd"
		return 0
	fi

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

	if [[ -d /etc/init.d ]] || [[ -d /etc/rc.d/init.d ]]; then
		_PKG_INIT_SYSTEM="sysv"
		return 0
	fi

	if [[ -f /etc/rc.local ]] || [[ -f /etc/rc.d/rc.local ]]; then
		_PKG_INIT_SYSTEM="rc.local"
		return 0
	fi

	return 0
}

# pkg_detect_pkgmgr — set _PKG_PKGMGR to dnf|yum|apt|emerge|pkg|slackpkg|unknown
# Idempotent; uses command -v cascade.
pkg_detect_pkgmgr() {
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

# pkg_is_systemd — return 0 if detected init system is systemd
pkg_is_systemd() {
	pkg_detect_init
	[[ "$_PKG_INIT_SYSTEM" = "systemd" ]]
}

# pkg_os_family — echo detected OS family (rhel|debian|gentoo|slackware|freebsd|unknown)
pkg_os_family() {
	pkg_detect_os
	echo "$_PKG_OS_FAMILY"
	return 0
}

# pkg_dep_hint pkg_rpm pkg_deb — print package-manager-specific install command
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

# pkg_check_dep binary pkg_rpm pkg_deb level — check one dependency (level=required|recommended|optional)
# Side effect: sets _PKG_DEPS_MISSING=1 for missing required deps.
pkg_check_dep() {
	local binary="$1" pkg_rpm="$2" pkg_deb="$3" level="${4:-required}"

	if [[ -z "$binary" ]]; then
		echo "pkg_lib: pkg_check_dep requires binary name" >&2
		return 1
	fi

	if command -v "$binary" >/dev/null 2>&1; then
		return 0
	fi

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

# pkg_check_deps prefix — batch check ${prefix}_DEP_{BINS,RPMS,DEBS,LEVELS} parallel arrays
# Indirect expansion, not declare -n (bash 4.1 compat floor).
pkg_check_deps() {
	local prefix="$1"

	if [[ -z "$prefix" ]]; then
		echo "pkg_lib: pkg_check_deps requires a variable prefix" >&2
		return 1
	fi

	# Indirect expansion via ${!ref} — bash 4.1 compat (no declare -n)
	local bins_ref="${prefix}_DEP_BINS[@]"
	local rpms_ref="${prefix}_DEP_RPMS[@]"
	local debs_ref="${prefix}_DEP_DEBS[@]"
	local levels_ref="${prefix}_DEP_LEVELS[@]"

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

PKG_BACKUP_METHOD="${PKG_BACKUP_METHOD:-move}"
PKG_BACKUP_SYMLINK="${PKG_BACKUP_SYMLINK:-.bk.last}"
PKG_BACKUP_PRUNE_DAYS="${PKG_BACKUP_PRUNE_DAYS:-0}"

# pkg_backup install_path [method] — timestamped backup (method: copy|move, default PKG_BACKUP_METHOD)
# Naming <install_path>.<DDMMYYYY-EPOCH>; appends -N on collision; updates PKG_BACKUP_SYMLINK.
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

	case "$method" in
		copy|move) ;;
		*)
			pkg_error "pkg_backup: invalid method '${method}' (must be copy or move)"
			return 1
			;;
	esac

	local timestamp
	timestamp="$(date +%d%m%Y)-$(date +%s)"

	local backup_path="${install_path}.${timestamp}"

	if [[ -e "$backup_path" ]]; then
		local suffix=1
		while [[ -e "${backup_path}-${suffix}" ]]; do
			suffix=$((suffix + 1))
		done
		backup_path="${backup_path}-${suffix}"
	fi

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

	local symlink_path
	symlink_path="$(dirname "$install_path")/${PKG_BACKUP_SYMLINK}"
	command rm -f "$symlink_path"
	ln -s "$backup_path" "$symlink_path" || {
		pkg_warn "pkg_backup: failed to create symlink ${symlink_path}"
	}

	pkg_info "backup created: ${backup_path}"
	return 0
}

# pkg_backup_exists install_path — return 0 if PKG_BACKUP_SYMLINK exists in parent dir
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

# pkg_backup_path install_path — echo PKG_BACKUP_SYMLINK target (1 if missing)
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

	local target
	target=$(readlink "$symlink_path") || {
		pkg_error "pkg_backup_path: failed to read symlink: ${symlink_path}"
		return 1
	}
	echo "$target"
	return 0
}

# pkg_backup_prune install_path max_age_days — remove backups older than N days (0 disables)
# Preserves the current PKG_BACKUP_SYMLINK target regardless of age.
pkg_backup_prune() {
	local install_path="$1"
	local max_age_days="$2"

	if [[ -z "$install_path" ]] || [[ -z "$max_age_days" ]]; then
		pkg_error "pkg_backup_prune: install_path and max_age_days required"
		return 1
	fi

	local int_pat='^[0-9]+$'
	if ! [[ "$max_age_days" =~ $int_pat ]]; then
		pkg_error "pkg_backup_prune: max_age_days must be a positive integer"
		return 1
	fi

	if [[ "$max_age_days" -eq 0 ]]; then
		return 0
	fi

	local parent_dir
	parent_dir="$(dirname "$install_path")"
	local base_name
	base_name="$(basename "$install_path")"

	# Resolve current PKG_BACKUP_SYMLINK target so we never prune it
	local current_backup=""
	local symlink_path="${parent_dir}/${PKG_BACKUP_SYMLINK}"
	if [[ -L "$symlink_path" ]]; then
		current_backup=$(readlink "$symlink_path" 2>/dev/null) || current_backup=""
	fi

	local bk_pat="^${base_name}\.[0-9]{8}-[0-9]+"
	local pruned=0
	local entry entry_path
	while IFS= read -r entry; do
		[[ -z "$entry" ]] && continue
		if ! [[ "$entry" =~ $bk_pat ]]; then
			continue
		fi
		entry_path="${parent_dir}/${entry}"

		if [[ -n "$current_backup" ]] && [[ "$entry_path" = "$current_backup" ]]; then
			continue
		fi

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

# pkg_restore_files backup_path install_path patterns... — selective file restore via find -name
# Preserves attributes and recreates parent directories. Returns 1 if no files matched.
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

	if [[ ! -d "$install_path" ]]; then
		mkdir -p "$install_path" || {
			pkg_error "pkg_restore_files: failed to create ${install_path}"
			return 1
		}
	fi

	local pattern restored=0 rc
	for pattern in "$@"; do
		while IFS= read -r match; do
			[[ -z "$match" ]] && continue
			local relpath="${match#"${backup_path}"/}"
			local dest="${install_path}/${relpath}"
			local dest_dir
			dest_dir="$(dirname "$dest")"

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

# pkg_restore_dir backup_path install_path subdir — restore entire subdirectory (creates parents)
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

# pkg_copy_tree src_dir dest_dir — recursive copy preserving ownership, perms, timestamps
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

# pkg_set_perms path dir_mode file_mode [exec_files...] — apply dir then file then exec mode
# Each exec_file (relative to path) is chmodded to dir_mode (typical exec bits).
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

	find "$base_path" -type d -exec chmod "$dir_mode" {} + 2>/dev/null  # best-effort: traversal errors on restricted dirs safe to ignore

	find "$base_path" -type f -exec chmod "$file_mode" {} + 2>/dev/null  # best-effort: traversal errors on restricted dirs safe to ignore

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

# pkg_create_dirs mode dirs... — mkdir -p each dir then chmod mode (1 if any creation fails)
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

# pkg_symlink target link_path — atomic create/update of a symlink
# Uses ln -sfn: single syscall (reduced TOCTOU) and -n avoids the ln -sf follow-into-dir gotcha.
pkg_symlink() {
	local target="$1"
	local link_path="$2"

	if [[ -z "$target" ]] || [[ -z "$link_path" ]]; then
		pkg_error "pkg_symlink: target and link_path required"
		return 1
	fi

	command ln -sfn "$target" "$link_path" || {
		pkg_error "pkg_symlink: failed to create symlink ${link_path} -> ${target}"
		return 1
	}

	return 0
}

# pkg_symlink_cleanup link_paths... — rm only symlinks, warn on non-symlinks, return 0
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

# pkg_sed_replace old_path new_path files... — sed -i across files with '|' delimiter
# Escapes old_path for BRE and new_path for replacement; missing files are skipped with warning.
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

	# BRE escape for search (.*[\^$&|/\); replacement escape for &|/\ only
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

# pkg_tmpfile [template] — mktemp wrapper in PKG_TMPDIR (default template pkg_lib.XXXXXXXXXX)
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

PKG_CHKCONFIG_LEVELS="${PKG_CHKCONFIG_LEVELS:-345}"
PKG_UPDATERCD_START="${PKG_UPDATERCD_START:-95}"
PKG_UPDATERCD_STOP="${PKG_UPDATERCD_STOP:-05}"
PKG_SYSTEMD_UNIT_DIR="${PKG_SYSTEMD_UNIT_DIR:-}"          # empty = auto-detect
PKG_SLACKWARE_RUNLEVELS="${PKG_SLACKWARE_RUNLEVELS:-2 3 4 5}"
PKG_SLACKWARE_PRIORITY="${PKG_SLACKWARE_PRIORITY:-95}"

# Private: rc.local search paths (override in tests)
_PKG_RCLOCAL_PATHS="${_PKG_RCLOCAL_PATHS:-/etc/rc.local /etc/rc.d/rc.local}"

# _pkg_systemd_unit_dir — echo systemd unit dir (env → /usr/lib → /lib, else 1)
_pkg_systemd_unit_dir() {
	if [[ -n "$PKG_SYSTEMD_UNIT_DIR" ]]; then
		echo "$PKG_SYSTEMD_UNIT_DIR"
		return 0
	fi

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

# _pkg_init_script_path name — echo SysV init script path (/etc/rc.d/init.d then /etc/init.d)
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

# _pkg_service_ctl action name — shared start/stop/restart cascade (systemd → SysV → error)
_pkg_service_ctl() {
	local action="$1" name="$2"

	if command -v systemctl >/dev/null 2>&1; then
		systemctl "$action" "$name" 2>/dev/null  # may fail if unit missing
		return $?
	fi

	local init_script
	if init_script=$(_pkg_init_script_path "$name"); then
		"$init_script" "$action"
		return $?
	fi

	pkg_error "no init method found for service: ${name}"
	return 1
}

# pkg_service_install name source_file — install unit or init script routed by detected init
# systemd → copy to unit dir + daemon-reload; SysV → copy to init.d + chmod 755.
pkg_service_install() {
	local name="$1" source_file="$2"

	if [[ -z "$name" ]] || [[ -z "$source_file" ]]; then
		pkg_error "pkg_service_install: name and source_file required"
		return 1
	fi

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

# pkg_service_uninstall name — exhaustive best-effort removal from all init locations
# Covers systemd units, SysV scripts, chkconfig, update-rc.d, rc-update, Slackware links, rc.local.
pkg_service_uninstall() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_uninstall: name required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

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

	local init_script
	if init_script=$(_pkg_init_script_path "$name"); then
		"$init_script" stop 2>/dev/null  # safe: ignore if already stopped
	fi

	if command -v chkconfig >/dev/null 2>&1; then
		chkconfig --del "$name" 2>/dev/null  # safe: ignore if not registered
	fi

	if command -v update-rc.d >/dev/null 2>&1; then
		update-rc.d -f "$name" remove 2>/dev/null  # safe: ignore if not registered
	fi

	if command -v rc-update >/dev/null 2>&1; then
		rc-update del "$name" default 2>/dev/null  # safe: ignore if not registered
	fi

	command rm -f "/etc/init.d/${name}" 2>/dev/null          # safe: may not exist
	command rm -f "/etc/rc.d/init.d/${name}" 2>/dev/null     # safe: may not exist

	local rl rc_dir
	for rl in 2 3 4 5; do
		rc_dir="/etc/rc.d/rc${rl}.d"
		if [[ -d "$rc_dir" ]]; then
			command rm -f "${rc_dir}/"S*"${name}" 2>/dev/null  # safe: glob may match nothing
		fi
	done

	pkg_rclocal_remove "$name"

	return 0
}

# pkg_service_install_timer name source_file — install a systemd timer unit (requires systemd)
pkg_service_install_timer() {
	local name="$1" source_file="$2"

	if [[ -z "$name" ]] || [[ -z "$source_file" ]]; then
		pkg_error "pkg_service_install_timer: name and source_file required"
		return 1
	fi

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

# pkg_service_install_multi name source_files... — install multiple units; routes .timer to _install_timer
pkg_service_install_multi() {
	local name="$1"
	shift

	if [[ -z "$name" ]] || [[ $# -eq 0 ]]; then
		pkg_error "pkg_service_install_multi: name and at least one source file required"
		return 1
	fi

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

# pkg_service_uninstall_multi name suffixes... — remove each ${name}${suffix} unit from all unit dirs
# suffixes are like ".service" ".timer" ".path"; runs a single daemon-reload after all removals.
pkg_service_uninstall_multi() {
	local name="$1"
	shift

	if [[ -z "$name" ]] || [[ $# -eq 0 ]]; then
		pkg_error "pkg_service_uninstall_multi: name and at least one suffix required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	local suffix
	for suffix in "$@"; do
		if command -v systemctl >/dev/null 2>&1; then
			systemctl stop "${name}${suffix}" 2>/dev/null    # safe: may not be running
			systemctl disable "${name}${suffix}" 2>/dev/null  # safe: may not be enabled
		fi
		command rm -f "/usr/lib/systemd/system/${name}${suffix}" 2>/dev/null  # safe: may not exist
		command rm -f "/lib/systemd/system/${name}${suffix}" 2>/dev/null      # safe: may not exist
	done

	if command -v systemctl >/dev/null 2>&1; then
		systemctl daemon-reload 2>/dev/null  # safe: refresh after bulk removal
	fi

	return 0
}

# pkg_service_start name — start service now
pkg_service_start() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_start: name required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	_pkg_service_ctl "start" "$name"
}

# pkg_service_stop name — stop service now
pkg_service_stop() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_stop: name required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	_pkg_service_ctl "stop" "$name"
}

# pkg_service_restart name — restart service now
pkg_service_restart() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_restart: name required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	_pkg_service_ctl "restart" "$name"
}

# pkg_service_status name — check if service is running (0=running, 1=stopped/unknown)
pkg_service_status() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_status: name required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	if command -v systemctl >/dev/null 2>&1; then
		systemctl is-active --quiet "$name" 2>/dev/null  # returns 0=active, non-zero=inactive
		return $?
	fi

	local init_script
	if init_script=$(_pkg_init_script_path "$name"); then
		"$init_script" status >/dev/null 2>&1
		return $?
	fi

	return 1
}

# pkg_service_enable name — enable at boot
# Cascade: systemd → chkconfig (RHEL) → update-rc.d (Debian) → rc-update (Gentoo) → Slackware links.
pkg_service_enable() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_enable: name required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	pkg_detect_init

	if [[ "$_PKG_INIT_SYSTEM" = "systemd" ]]; then
		systemctl enable "$name" 2>/dev/null  # may fail if unit missing
		return $?
	fi

	if [[ "$_PKG_OS_FAMILY" = "rhel" ]]; then
		if command -v chkconfig >/dev/null 2>&1; then
			chkconfig --add "$name" 2>/dev/null  # safe: may already exist
			chkconfig --level "$PKG_CHKCONFIG_LEVELS" "$name" on
			return $?
		fi
	fi

	if [[ "$_PKG_OS_FAMILY" = "debian" ]]; then
		if command -v update-rc.d >/dev/null 2>&1; then
			update-rc.d "$name" defaults "$PKG_UPDATERCD_START" "$PKG_UPDATERCD_STOP"
			return $?
		fi
	fi

	if [[ "$_PKG_OS_FAMILY" = "gentoo" ]]; then
		if command -v rc-update >/dev/null 2>&1; then
			rc-update add "$name" default
			return $?
		fi
	fi

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

	pkg_warn "pkg_service_enable: unsupported init system for enable: ${_PKG_INIT_SYSTEM}"
	return 1
}

# pkg_service_disable name — reversible disable (cascade mirrors pkg_service_enable)
# Does NOT remove init scripts — use pkg_service_uninstall for full removal.
pkg_service_disable() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_disable: name required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	pkg_detect_init

	if [[ "$_PKG_INIT_SYSTEM" = "systemd" ]]; then
		systemctl disable "$name" 2>/dev/null  # may fail if unit missing
		return $?
	fi

	# RHEL: chkconfig off (reversible — not --del)
	if [[ "$_PKG_OS_FAMILY" = "rhel" ]]; then
		if command -v chkconfig >/dev/null 2>&1; then
			chkconfig "$name" off
			return $?
		fi
	fi

	if [[ "$_PKG_OS_FAMILY" = "debian" ]]; then
		if command -v update-rc.d >/dev/null 2>&1; then
			update-rc.d "$name" disable
			return $?
		fi
	fi

	if [[ "$_PKG_OS_FAMILY" = "gentoo" ]]; then
		if command -v rc-update >/dev/null 2>&1; then
			rc-update del "$name" default
			return $?
		fi
	fi

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

	pkg_warn "pkg_service_disable: unsupported init system for disable: ${_PKG_INIT_SYSTEM}"
	return 1
}

# pkg_service_exists name — check if unit file or init script is installed (0=yes, 1=no)
pkg_service_exists() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_exists: name required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	local unit_dir
	if unit_dir=$(_pkg_systemd_unit_dir); then
		if [[ -f "${unit_dir}/${name}.service" ]] || [[ -f "${unit_dir}/${name}.timer" ]]; then
			return 0
		fi
	fi

	# Check both systemd dirs explicitly — auto-detect may have picked only one
	if [[ -f "/usr/lib/systemd/system/${name}.service" ]] || \
	   [[ -f "/lib/systemd/system/${name}.service" ]]; then
		return 0
	fi

	if _pkg_init_script_path "$name" >/dev/null 2>&1; then
		return 0
	fi

	return 1
}

# pkg_service_is_enabled name — check if service is enabled at boot (0=enabled, 1=not)
pkg_service_is_enabled() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_service_is_enabled: name required"
		return 1
	fi

	pkg_detect_os
	if [[ "$_PKG_OS_ID" = "freebsd" ]]; then
		pkg_warn "FreeBSD service management not supported"
		return 1
	fi

	pkg_detect_init

	if [[ "$_PKG_INIT_SYSTEM" = "systemd" ]]; then
		if command -v systemctl >/dev/null 2>&1; then
			systemctl is-enabled --quiet "$name" 2>/dev/null
			return $?
		fi
		return 1
	fi

	if [[ "$_PKG_OS_FAMILY" = "rhel" ]]; then
		if command -v chkconfig >/dev/null 2>&1; then
			chkconfig "$name" 2>/dev/null  # returns 0 if on
			return $?
		fi
	fi

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

	if [[ "$_PKG_OS_FAMILY" = "gentoo" ]]; then
		if command -v rc-update >/dev/null 2>&1; then
			rc-update show default 2>/dev/null | grep -q "$name"
			return $?
		fi
	fi

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

# pkg_rclocal_add entry — idempotent add to first _PKG_RCLOCAL_PATHS entry (creates if missing)
# New file gets #!/bin/bash header and 0755 mode.
pkg_rclocal_add() {
	local entry="$1"

	if [[ -z "$entry" ]]; then
		pkg_error "pkg_rclocal_add: entry required"
		return 1
	fi

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

	if grep -qF "$entry" "$rclocal" 2>/dev/null; then
		return 0
	fi

	printf '%s\n' "$entry" >> "$rclocal" || {
		pkg_error "pkg_rclocal_add: failed to append to ${rclocal}"
		return 1
	}

	return 0
}

# pkg_rclocal_remove pattern — strip matching lines from every _PKG_RCLOCAL_PATHS entry
# Atomic replace via grep -v + mktemp + mv; original file mode preserved.
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

		if ! grep -qF "$pattern" "$path" 2>/dev/null; then
			continue
		fi

		# GNU stat for Linux, BSD stat for FreeBSD; 755 fallback if both fail
		local _orig_mode
		_orig_mode=$(command stat -Lc '%a' "$path" 2>/dev/null) || \
			_orig_mode=$(command stat -Lf '%OLp' "$path" 2>/dev/null) || \
			_orig_mode="755"

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

		# Restore mode: mktemp creates 0600 but rc.local needs its original perms
		command chmod "$_orig_mode" "$path" || \
			pkg_warn "pkg_rclocal_remove: failed to restore permissions on ${path}"
	done

	return 0
}

# pkg_cron_install src dest [mode] — install cron file, auto-mode from dest when omitted
# Auto: 755 for cron.{daily,hourly,weekly,monthly} (executed); 644 elsewhere (cron.d tables).
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

	if [[ -z "$mode" ]]; then
		local cron_exec_pat='cron\.(daily|hourly|weekly|monthly)'
		if [[ "$dest" =~ $cron_exec_pat ]]; then
			mode="755"
		else
			mode="644"
		fi
	fi

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

# pkg_cron_remove paths... — best-effort removal, warns on failure
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

# pkg_cron_cleanup_legacy patterns... — expand each arg as a glob and remove matches
pkg_cron_cleanup_legacy() {
	if [[ $# -eq 0 ]]; then
		pkg_error "pkg_cron_cleanup_legacy: at least one pattern required"
		return 1
	fi

	local pattern path
	for pattern in "$@"; do
		for path in $pattern; do
			if [[ -f "$path" ]]; then
				command rm -f "$path" || pkg_warn "pkg_cron_cleanup_legacy: failed to remove ${path}"
			fi
		done
	done

	return 0
}

# _pkg_cron_read_schedule cron_file — echo the first 5 fields of the first cron line
# Skips comments, blank lines, and VAR=value assignments. Returns 1 if no schedule line found.
_pkg_cron_read_schedule() {
	local cron_file="$1"
	local line schedule=""
	local comment_pat='^[[:space:]]*(#|$)'
	local assign_pat='^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*='

	while IFS= read -r line; do
		if [[ "$line" =~ $comment_pat ]]; then
			continue
		fi
		if [[ "$line" =~ $assign_pat ]]; then
			continue
		fi
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

# pkg_cron_preserve_schedule cron_file var_name — capture first cron schedule into named var
# var_name is validated as a safe shell identifier before eval assignment.
pkg_cron_preserve_schedule() {
	local cron_file="$1" var_name="$2"

	if [[ -z "$cron_file" ]] || [[ -z "$var_name" ]]; then
		pkg_error "pkg_cron_preserve_schedule: cron_file and var_name required"
		return 1
	fi

	if [[ ! -f "$cron_file" ]]; then
		return 1
	fi

	local valid_ident='^[A-Za-z_][A-Za-z0-9_]*$'
	if ! [[ "$var_name" =~ $valid_ident ]]; then
		pkg_error "pkg_cron_preserve_schedule: invalid variable name: ${var_name}"
		return 1
	fi

	local schedule
	schedule=$(_pkg_cron_read_schedule "$cron_file") || return 1

	# Safe: var_name validated above as shell identifier
	eval "${var_name}=\${schedule}"
	return 0
}

# pkg_cron_restore_schedule cron_file old_schedule — replace first cron schedule with old_schedule
# Sed-escapes '*' and other metachars in both search and replacement; no-op if schedules match.
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

	local current_schedule
	current_schedule=$(_pkg_cron_read_schedule "$cron_file") || {
		pkg_warn "pkg_cron_restore_schedule: no cron line found in ${cron_file}"
		return 1
	}

	if [[ "$current_schedule" = "$old_schedule" ]]; then
		return 0
	fi

	# BRE escape for search (.*[\^$/\); replacement escape for &/\ only
	local esc_current esc_old
	esc_current=$(printf '%s' "$current_schedule" | sed 's/[.*[\^$/\\]/\\&/g')
	esc_old=$(printf '%s' "$old_schedule" | sed 's/[&/\\]/\\&/g')

	# sed address range limits to first occurrence only
	sed -i "0,/${esc_current}/s/${esc_current}/${esc_old}/" "$cron_file" || {
		pkg_warn "pkg_cron_restore_schedule: sed replacement failed on ${cron_file}"
		return 1
	}

	return 0
}

# _pkg_man_dir section — echo man dir (/usr/share → /usr/local/share, else mkdir /usr/share)
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

	local fallback="/usr/share/man/man${section}"
	mkdir -p "$fallback" || {
		pkg_error "_pkg_man_dir: failed to create ${fallback}"
		return 1
	}
	echo "$fallback"
	return 0
}

# pkg_man_install src section name [sed_pairs...] — gzip and install as name.section.gz
# sed_pairs are "old|new" strings applied to a temp copy before compression.
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

	local pair old_str new_str esc_old esc_new
	for pair in "$@"; do
		old_str="${pair%%|*}"
		new_str="${pair#*|}"
		if [[ -n "$old_str" ]]; then
			# BRE escape for search (.*[\^$&|/\); replacement escape for &|/\ only
			esc_old=$(printf '%s' "$old_str" | sed 's/[.*[\^$&|/\\]/\\&/g')
			esc_new=$(printf '%s' "$new_str" | sed 's/[&|/\\]/\\&/g')
			sed -i "s|${esc_old}|${esc_new}|g" "$tmpfile" || {
				pkg_warn "pkg_man_install: sed replacement failed for pair: ${pair}"
			}
		fi
	done

	gzip -f "$tmpfile" || {
		pkg_error "pkg_man_install: gzip failed"
		command rm -f "$tmpfile"
		return 1
	}

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

# _pkg_install_sysfile src name dest_dir func_name — shared 0644 install helper
# func_name is used for error-message attribution to the caller.
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

# pkg_bash_completion src name — install to /etc/bash_completion.d/ with mode 644
pkg_bash_completion() {
	_pkg_install_sysfile "$1" "$2" "/etc/bash_completion.d" "pkg_bash_completion" || return 1
	pkg_info "installed bash completion: ${2}"
	return 0
}

# pkg_logrotate_install src name — install to /etc/logrotate.d/ with mode 644
pkg_logrotate_install() {
	_pkg_install_sysfile "$1" "$2" "/etc/logrotate.d" "pkg_logrotate_install" || return 1
	pkg_info "installed logrotate config: ${2}"
	return 0
}

# pkg_doc_install dest_dir files... — copy doc files into dest_dir (creates if missing)
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

# pkg_config_get conf_file var — echo raw VAR=value bytes from first matching line
# Strips surrounding quotes. Raw bytes are NOT shell-interpreted — escape sequences
# (\\", \\$) are returned literally. Source the file instead to get shell-interpreted values.
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

	local _varname_re='^[a-zA-Z_][a-zA-Z0-9_]*$'
	if [[ ! "$var" =~ $_varname_re ]]; then
		pkg_error "pkg_config_get: invalid variable name: ${var}"
		return 1
	fi

	local value
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
		# Distinguish empty value from missing variable
		if grep -q "^[[:space:]]*${var}=" "$conf_file"; then
			echo ""
			return 0
		fi
		return 1
	fi

	echo "$value"
	return 0
}

# pkg_config_set conf_file var val — sed-replace existing VAR= line or append VAR="value"
# val is shell-escaped for double-quote context before sed replacement.
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

	# Reject metacharacter-bearing names to prevent regex/sed injection
	local _varname_re='^[a-zA-Z_][a-zA-Z0-9_]*$'
	if [[ ! "$var" =~ $_varname_re ]]; then
		pkg_error "pkg_config_set: invalid variable name: ${var}"
		return 1
	fi

	# Shell-escape for double-quote context: \ first to avoid double-escaping
	local _shell_val="${val//\\/\\\\}"
	_shell_val="${_shell_val//\"/\\\"}"
	_shell_val="${_shell_val//\$/\\\$}"
	_shell_val="${_shell_val//\`/\\\`}"

	# Escape for sed replacement; pipe must be escaped because outer sed uses | as delimiter
	local esc_val
	esc_val=$(printf '%s' "$_shell_val" | sed 's/[&|/\]/\\&/g')

	if grep -q "^[[:space:]]*${var}=" "$conf_file"; then
		sed -i "s|^[[:space:]]*${var}=.*|${var}=\"${esc_val}\"|" "$conf_file" || {
			pkg_error "pkg_config_set: sed failed on ${conf_file}"
			return 1
		}
	else
		printf '%s="%s"\n' "$var" "$_shell_val" >> "$conf_file" || {
			pkg_error "pkg_config_set: failed to append to ${conf_file}"
			return 1
		}
	fi

	return 0
}

# pkg_config_merge old_conf new_conf output — AWK two-pass merge of old values into new template
# Anchors to real shell assignments (^[[:space:]]*IDENT=); conditional-expression lines like
# `[ "$X" = "1" ]` or `[[ "$Y" == "auto" ]]` pass through unchanged. Files that assign the
# same variable in multiple branches remain unsafe — last-seen value collapses both branches,
# so only use on flat VAR=value config files.
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

	local output_dir
	output_dir=$(dirname "$output")
	if [[ ! -d "$output_dir" ]]; then
		mkdir -p "$output_dir" || {
			pkg_error "pkg_config_merge: failed to create output directory ${output_dir}"
			return 1
		}
	fi

	# stat -c is GNU (all supported Linux targets); FreeBSD uses stat -f '%OLp'
	local _preserve_mode=""
	if [[ -f "$new_conf" ]]; then
		_preserve_mode=$(stat -Lc '%a' "$new_conf" 2>/dev/null) || \
			_preserve_mode=$(stat -Lf '%OLp' "$new_conf" 2>/dev/null) || \
			_preserve_mode=""
	fi

	# Uses FILENAME instead of FNR==NR so an empty old config still reaches the template pass
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

# pkg_config_migrate_var conf_file old_var new_var [transform] — rename VAR, apply case transform
# transform: none|lower|upper (default none). No-op if old_var missing or new_var already set.
# Leaves a migration comment in the file for traceability.
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

	local _varname_re='^[a-zA-Z_][a-zA-Z0-9_]*$'
	if [[ ! "$old_var" =~ $_varname_re ]]; then
		pkg_error "pkg_config_migrate_var: invalid variable name: ${old_var}"
		return 1
	fi
	if [[ ! "$new_var" =~ $_varname_re ]]; then
		pkg_error "pkg_config_migrate_var: invalid variable name: ${new_var}"
		return 1
	fi

	if ! grep -q "^[[:space:]]*${old_var}=" "$conf_file"; then
		return 0
	fi

	if grep -q "^[[:space:]]*${new_var}=" "$conf_file"; then
		# New var already set — comment out the orphan old_var
		sed -i "s|^[[:space:]]*${old_var}=|# migrated to ${new_var}: ${old_var}=|" "$conf_file"
		return 0
	fi

	local old_val
	old_val=$(pkg_config_get "$conf_file" "$old_var") || old_val=""

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

	# AWK raw reader returns literal bytes between quotes; single-quoted originals lack
	# escape sequences, so rewriting them in double quotes without escaping is an injection vector.
	# Escape \, ", $, ` for double-quote context (backslash first to avoid double-escaping).
	local _shell_val="${old_val//\\/\\\\}"
	_shell_val="${_shell_val//\"/\\\"}"
	_shell_val="${_shell_val//\$/\\\$}"
	_shell_val="${_shell_val//\`/\\\`}"

	local esc_val
	esc_val=$(printf '%s' "$_shell_val" | sed 's/[&|/\]/\\&/g')

	sed -i "s|^[[:space:]]*${old_var}=.*|# migrated: ${old_var} -> ${new_var}\n${new_var}=\"${esc_val}\"|" "$conf_file" || {
		pkg_error "pkg_config_migrate_var: sed failed on ${conf_file}"
		return 1
	}

	return 0
}

# pkg_config_clamp conf_file var max_val [msg] — clamp numeric value to max_val and warn
# No-op if variable not found, value is non-numeric, or already within range.
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

	local numeric_pat='^[0-9]+$'
	if ! [[ "$max_val" =~ $numeric_pat ]]; then
		pkg_error "pkg_config_clamp: max_val must be a positive integer"
		return 1
	fi

	local current_val
	current_val=$(pkg_config_get "$conf_file" "$var") || return 0  # not found = no-op

	if ! [[ "$current_val" =~ $numeric_pat ]]; then
		return 0  # non-numeric value — skip clamping
	fi

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

# FHS registry — parallel indexed arrays (bash 4.1 compat: no declare -A globals)
# Populated by pkg_fhs_register(), consumed by pkg_fhs_install() and generators.
_PKG_FHS_SRCS=()
_PKG_FHS_DESTS=()
_PKG_FHS_MODES=()
_PKG_FHS_TYPES=()

# pkg_fhs_register src fhs_dest mode [type] — register a mapping into the FHS registry
# type: bin|lib|conf|data|state|doc (default "data"); mode validated as 3-4 digit octal.
pkg_fhs_register() {
	local src="$1" fhs_dest="$2" mode="$3" ftype="${4:-data}"

	if [[ -z "$src" ]] || [[ -z "$fhs_dest" ]] || [[ -z "$mode" ]]; then
		pkg_error "pkg_fhs_register: src, fhs_dest, and mode required"
		return 1
	fi

	case "$ftype" in
		bin|lib|conf|data|state|doc) ;;
		*)
			pkg_error "pkg_fhs_register: invalid type '${ftype}' (expected bin|lib|conf|data|state|doc)"
			return 1
			;;
	esac

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

# pkg_fhs_install src_dir — copy each registered src_dir/src to its fhs_dest with registered mode
# Creates parent dirs; continues on failure and returns 1 if any copy failed.
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

		if [[ ! -d "$dest_dir" ]]; then
			mkdir -p "$dest_dir" || {
				pkg_error "pkg_fhs_install: failed to create directory ${dest_dir}"
				rc=1
				failed=$((failed + 1))
				continue
			}
		fi

		# Directory-type sources are state dirs and similar
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

		chmod "${_PKG_FHS_MODES[$i]}" "$dest_path" 2>/dev/null  # best-effort chmod
	done

	local installed=$((count - failed))
	if [[ "$installed" -gt 0 ]]; then
		pkg_info "installed ${installed} file(s) to FHS layout"
	fi

	return "$rc"
}

# pkg_fhs_symlink_farm legacy_root — create legacy-path → FHS symlinks for each registered file
# Keeps old scripts/configs that reference legacy paths working after the FHS migration.
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

		if [[ ! -d "$link_dir" ]]; then
			mkdir -p "$link_dir" || {
				pkg_error "pkg_fhs_symlink_farm: failed to create ${link_dir}"
				rc=1
				failed=$((failed + 1))
				continue
			}
		fi

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

# pkg_fhs_symlink_farm_cleanup legacy_root — remove symlinks created by pkg_fhs_symlink_farm
# Skips non-symlinks for safety; empty parent dirs under legacy_root are pruned afterward.
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

	if [[ -d "$legacy_root" ]]; then
		find "$legacy_root" -type d -empty -delete 2>/dev/null  # best-effort cleanup
	fi

	return 0
}

# pkg_fhs_gen_rpm_files — emit RPM %files lines from the FHS registry
# Config files get %config(noreplace); parent dirs get %dir. Registry must be pre-populated.
pkg_fhs_gen_rpm_files() {
	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		return 0
	fi

	local seen_dirs="" i dest ftype dest_dir

	for ((i = 0; i < count; i++)); do
		dest="${_PKG_FHS_DESTS[$i]}"
		ftype="${_PKG_FHS_TYPES[$i]}"
		dest_dir="$(dirname "$dest")"

		case "$seen_dirs" in
			*"|${dest_dir}|"*) ;;
			*)
				echo "%dir ${dest_dir}"
				seen_dirs="${seen_dirs}|${dest_dir}|"
				;;
		esac

		if [[ "$ftype" = "conf" ]]; then
			echo "%config(noreplace) ${dest}"
		else
			echo "${dest}"
		fi
	done

	return 0
}

# pkg_fhs_gen_deb_dirs — emit unique DEB dirs file entries (one path per line)
pkg_fhs_gen_deb_dirs() {
	local count=${#_PKG_FHS_SRCS[@]}
	if [[ "$count" -eq 0 ]]; then
		return 0
	fi

	local seen_dirs="" i dest_dir

	for ((i = 0; i < count; i++)); do
		dest_dir="$(dirname "${_PKG_FHS_DESTS[$i]}")"

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

# pkg_fhs_gen_deb_links legacy_root — emit "fhs_dest legacy_path" pairs (DEB links format)
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

# pkg_fhs_gen_deb_conffiles — emit absolute paths of registry entries with type=conf
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

# pkg_fhs_gen_sed_pairs install_path_var — emit -e 's|dest_dir|$VAR|g' for each unique FHS dir
# Used by install.sh to patch shipped scripts at install time.
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

# pkg_fhs_gen_manifest legacy_root — emit tab-separated "legacy_path\tfhs_dest" manifest
# Produced at build time, consumed at runtime by pkg_fhs_verify_farm(). Header line:
# "# pkg_lib:symlink-manifest:1".
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

# pkg_fhs_verify_farm manifest_path — verify and self-repair the symlink farm from manifest
# Repairs broken, wrong-target, and regular-file-blocked links when the target exists.
# Returns 1 if any target is missing or a directory blocks a symlink path. No manifest = 0
# silently (install.sh layout has no symlink farm).
pkg_fhs_verify_farm() {
	local manifest_path="$1"

	if [[ -z "$manifest_path" ]]; then
		pkg_error "pkg_fhs_verify_farm: manifest_path required"
		return 1
	fi

	if [[ ! -f "$manifest_path" ]]; then
		return 0
	fi

	local rc=0
	local link_path target

	while IFS=$'\t' read -r link_path target; do
		[[ -z "$link_path" ]] && continue
		[[ "$link_path" = \#* ]] && continue
		if [[ -z "$target" ]]; then
			pkg_warn "malformed manifest line: ${link_path}"
			continue
		fi

		if [[ -L "$link_path" ]]; then
			local current_target
			current_target=$(readlink "$link_path")
			if [[ "$current_target" = "$target" ]]; then
				if [[ -e "$link_path" ]]; then
					continue
				fi
				pkg_error "symlink target missing: ${target} — reinstall package"
				rc=1
				continue
			fi

			# Wrong target but still resolves — repair in place
			if [[ -e "$link_path" ]]; then
				pkg_symlink "$target" "$link_path"
				pkg_warn "repaired symlink (wrong target): ${link_path}"
				continue
			fi

			# Dangling with wrong target — only repair if correct target exists
			if [[ -e "$target" ]]; then
				pkg_symlink "$target" "$link_path"
				pkg_warn "repaired symlink: ${link_path} -> ${target}"
			else
				pkg_error "symlink target missing: ${target} — reinstall package"
				rc=1
			fi
			continue
		fi

		if [[ -d "$link_path" ]]; then
			pkg_error "directory exists at symlink path: ${link_path} — remove manually"
			rc=1
			continue
		fi

		if [[ -e "$link_path" ]]; then
			pkg_symlink "$target" "$link_path"
			pkg_warn "replaced regular file with symlink: ${link_path}"
			continue
		fi

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

# pkg_uninstall_confirm project_name — interactive y/N prompt (0=confirmed, 1=declined)
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

# pkg_uninstall_files paths... — best-effort rm of files (rm -f) and dirs (rm -rf)
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

# pkg_uninstall_man section name — remove uncompressed and gzipped man page from standard dirs
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

# pkg_uninstall_cron paths... — best-effort rm of cron files (skips missing paths)
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

# pkg_uninstall_logrotate name — best-effort rm of /etc/logrotate.d/$name
pkg_uninstall_logrotate() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_uninstall_logrotate: name required"
		return 1
	fi

	command rm -f "/etc/logrotate.d/${name}" 2>/dev/null  # best-effort removal
	return 0
}

# pkg_uninstall_completion name — best-effort rm of /etc/bash_completion.d/$name
pkg_uninstall_completion() {
	local name="$1"

	if [[ -z "$name" ]]; then
		pkg_error "pkg_uninstall_completion: name required"
		return 1
	fi

	command rm -f "/etc/bash_completion.d/${name}" 2>/dev/null  # best-effort removal
	return 0
}

# pkg_uninstall_sysconfig name — rm /etc/sysconfig/$name (RHEL) and /etc/default/$name (Debian)
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

# pkg_manifest_load manifest_file — source a project manifest (plain key="value" bash file)
# Defense-in-depth: refuses manifests not owned by the current user.
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

# pkg_manifest_validate — require PKG_{NAME,VERSION,SUMMARY,INSTALL_PATH} to be non-empty
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
