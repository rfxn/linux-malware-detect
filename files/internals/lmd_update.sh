#!/usr/bin/env bash
# shellcheck shell=bash
# shellcheck disable=SC1090,SC1091
##
# Linux Malware Detect v2.0.1
#             (C) 2002-2026, R-fx Networks <proj@rfxn.com>
#             (C) 2026, Ryan MacDonald <ryan@rfxn.com>
# This program may be freely redistributed under the terms of the GNU GPL v2
##
# Version update, signature update, and checkout

# Source guard
[[ -n "${_LMD_UPDATE_LOADED:-}" ]] && return 0 2>/dev/null
_LMD_UPDATE_LOADED=1

checkout() {
	if ! command -v ftp >/dev/null 2>&1; then
		eout "{checkout} ftp binary not found, unable to upload" 1
		return 1
	fi
	local file="$1"
	host=ftp.rfxn.com
	user=anonymous@rfxn.com
	passwd=anonymous@rfxn.com
	upath=incoming

	cfile="$startdir/$file"
	if [ -f "$cfile" ]; then
		file="$cfile"
	fi

	if [ -f "$file" ]; then

		filename=$(basename "$file" | tr -d '[:cntrl:]' | tr -d '[:space:]')
		if [ -z "$filename" ]; then
			storename="$storename_prefix"
		else
			storename="$storename_prefix.$filename"
		fi

		eout "{checkout} uploading $file to $host" 1

(ftp -v -n -p -i $host || ftp -v -n -i $host) << EOT
user $user $passwd
prompt
cd $upath
binary
put "$file" "$storename.bin"
ascii
put "$file" "$storename.ascii"
bye
EOT

	elif [ -d "$file" ]; then
		tmpf=$(mktemp "$tmpdir/.co.XXXXXX")
		find "$file" -type f > "$tmpf"
		cofiles=$($wc -l < "$tmpf")
		if [ "$cofiles" -ge "50" ]; then
			eout "{checkout} path $file contains $cofiles files, limit of 50 file uploads, aborting!" 1
			command rm -f "$tmpf"
			return 1
		fi
		while IFS= read -r i; do
			filename="${i##*/}"
			filename=$(echo "$filename" | tr -d '[:cntrl:]' | tr -d '[:space:]')
			if [ -z "$filename" ]; then
				storename="$storename_prefix"
			else
				storename="$storename_prefix.$filename"
			fi
(ftp -v -n -p -i $host || ftp -v -n -i $host) << EOT
user $user $passwd
prompt
cd $upath
binary
put "$i" "$storename.bin"
ascii
put "$i" "$storename.ascii"
bye
EOT
		done < "$tmpf"
	else
		eout "{checkout} $file not found" 1
		return 1
	fi
}

_verify_download() {
	# Verify integrity of a downloaded file against its hash sidecar.
	# Prefers SHA-256; falls back to MD5 if sha256sum binary is absent.
	# Returns: 0 = verified, 1 = mismatch/failure
	local _file="$1" _sidecar_url_base="$2" _svc="$3" _local_base="$4"
	local _hash_bin _sidecar_ext _hash_label

	if [ -n "$sha256sum" ]; then
		_hash_bin="$sha256sum"
		_sidecar_ext=".sha256"
		_hash_label="sha256sum"
	else
		eout "{$_svc} sha256sum not available, falling back to md5 verification" 1
		_hash_bin="$md5sum"
		_sidecar_ext=".md5"
		_hash_label="md5sum"
	fi

	get_remote_file "${_sidecar_url_base}${_sidecar_ext}" "$_svc" "1" "${_local_base}${_sidecar_ext}"

	if [ -f "${_local_base}${_sidecar_ext}" ] && [ -s "${_local_base}${_sidecar_ext}" ]; then
		local _upstream_hash _local_hash
		_upstream_hash=$(awk '{print$1}' "${_local_base}${_sidecar_ext}")
		_local_hash=$($_hash_bin "$_file" | awk '{print$1}')
		if [ "$_upstream_hash" != "$_local_hash" ]; then
			eout "{$_svc} unable to verify $_hash_label of $(basename "$_file"), please try again" 1
			return 1
		else
			eout "{$_svc} verified $_hash_label of $(basename "$_file")" 1
			return 0
		fi
	else
		eout "{$_svc} could not download ${_sidecar_url_base}${_sidecar_ext}" 1
		return 1
	fi
}

lmdup() {
	tmpwd=$(mktemp -d "$tmpdir/.lmdup.XXXXXX")
	upstreamver="$tmpwd/.lmdup_vercheck"
	chmod 700 "$tmpwd"

	if [ "$lmdup_beta" ]; then
		lmd_hash_sha256_url="${lmd_hash_sha256_url}.beta"
		lmd_hash_url="${lmd_hash_url}.beta"
		lmd_version_url="${lmd_version_url}.beta"
		lmd_current_tgzfile="maldetect-beta.tar.gz"
	fi

	eout "{update} checking for available updates..." 1
	get_remote_file "$lmd_version_url" "update" "1"
	upstreamver="$return_file"
	if [ -s "$upstreamver" ]; then
		installedver=$(echo $lmd_version | tr -d '.')
		if [ "$(echo $installedver | $wc -L)" -eq "2" ]; then
			installedver="${installedver}0"
		fi
		upstreamver_readable=$(tr -d '[:space:]' < "$upstreamver")
		local _ver_re='^[0-9]+\.[0-9]+\.[0-9]+$'
		if ! [[ "$upstreamver_readable" =~ $_ver_re ]]; then
			eout "{update} upstream version string failed format validation: '$upstreamver_readable'" 1
			_grf_cleanup
			cd "$inspath" || true  # safe: cleanup and exit follow
			command rm -rf "$tmpwd"
			clean_exit
			exit 1
		fi
		upstreamver=$(tr -d '.' < "$upstreamver")
		if [ "$(echo $upstreamver | $wc -L)" -eq "2" ]; then
			upstreamver="${upstreamver}0"
		fi
		if [ "$upstreamver" -gt "$installedver" ]; then
			eout "{update} new version $upstreamver_readable found, updating..." 1
			doupdate=1
		elif [ "$lmdup_force" ]; then
			eout "{update} version update with --force requested, updating..." 1
			doupdate=1
		elif [ "$autoupdate_version_hashed" == "1" ]; then
			eout "{update} hashing install files and checking against server..." 1
			local _hash_bin _hash_remote_url
			if [ -n "$sha256sum" ]; then
				_hash_bin="$sha256sum"
				_hash_remote_url="$lmd_hash_sha256_url"
			else
				eout "{update} sha256sum not available, falling back to md5 verification" 1
				_hash_bin="$md5sum"
				_hash_remote_url="$lmd_hash_url"
			fi
			$_hash_bin "$inspath/maldet" "$intfunc" | awk '{print$1}' | tr '\n' ' ' | tr -d ' ' > "$lmd_hash_file"
			get_remote_file "$_hash_remote_url" "update" "1"
			upstreamhash="$return_file"
			if [ -s "$upstreamhash" ]; then
				installed_hash=$(cat "$lmd_hash_file")
				current_hash=$(cat "$upstreamhash")
				if [ "$installed_hash" != "$current_hash" ]; then
					eout "{update} version check shows latest but hash check failed, forcing update..." 1
					doupdate=1
				else
					eout "{update} latest version already installed." 1
				fi
			else
				eout "{update} could not download upstream hash file ($_hash_remote_url), please try again later." 1
				_grf_cleanup
				cd "$inspath" || true  # safe: cleanup and exit follow
				command rm -rf "$tmpwd"
				clean_exit
				exit 1
			fi
		else
			eout "{update} no updates available, latest version already installed." 1
		fi
	else
		eout "{update} could not download version file from server, please try again later." 1
		_grf_cleanup
		cd "$inspath" || true  # safe: cleanup and exit follow
		command rm -rf "$tmpwd"
		clean_exit
		exit 1
	fi
	if [ "$doupdate" ]; then
		_lmd_elog_event "$ELOG_EVT_UPDATE_STARTED" "info" "version update started" "action=lmdup" "version=$upstreamver_readable"
		cd "$tmpwd/" || { eout "{update} failed to cd to temp dir, aborting update" 1; command rm -rf "$tmpwd"; exit 1; }

		get_remote_file "${lmd_current_tgzbase_url}/${lmd_current_tgzfile}" "update" "1" "$tmpwd/${lmd_current_tgzfile}"

		if [ ! -s "$tmpwd/${lmd_current_tgzfile}" ]; then
			eout "{update} could not download ${lmd_current_tgzfile}, please try again later." 1
			_lmd_elog_event "$ELOG_EVT_UPDATE_FAILED" "error" "version update failed" "action=lmdup" "reason=download_failed"
			cd "$inspath" ; command rm -rf "$tmpwd"
			clean_exit
			exit 1
		fi
		if ! _verify_download "$tmpwd/${lmd_current_tgzfile}" \
				"${lmd_current_tgzbase_url}/${lmd_current_tgzfile}" \
				"update" "$tmpwd/${lmd_current_tgzfile}"; then
			_lmd_elog_event "$ELOG_EVT_UPDATE_FAILED" "error" "version update failed" "action=lmdup" "reason=verify_failed"
			cd "$inspath" ; command rm -rf "$tmpwd"
			clean_exit
			exit 1
		fi
		if [ -s "$tmpwd/${lmd_current_tgzfile}" ]; then
			tar --no-same-owner -xzf "${lmd_current_tgzfile}"
			command rm -f "${lmd_current_tgzfile}" "${lmd_current_tgzfile}".{sha256,md5}
			cd "maldetect-${upstreamver_readable}" || { eout "{update} failed to cd to extracted directory maldetect-${upstreamver_readable}, aborting update" 1; cd "$inspath"; command rm -rf "$tmpwd"; clean_exit; exit 1; }
			chmod 750 install.sh
			local install_log
			install_log=$(mktemp "$tmpdir/.lmdup_install.XXXXXX")
			local install_rc
			sh -c './install.sh' > "$install_log" 2>&1
			install_rc=$?
			if [ "$install_rc" -ne 0 ]; then
				eout "{update} install.sh failed with exit code $install_rc" 1
				_lmd_elog_event "$ELOG_EVT_UPDATE_FAILED" "error" "version update failed" "action=lmdup" "reason=install_failed" "rc=$install_rc"
				if [ -s "$install_log" ]; then
					eout "{update} install.sh output: $(cat "$install_log")" 0
				fi
				command rm -f "$install_log"
				cd "$inspath" ; command rm -rf "$tmpwd"
				clean_exit
				exit 1
			fi
			command rm -f "$install_log"
			command cp -f "$inspath.last/sigs/custom."* "$sigdir/" 2> /dev/null
			command cp -f "$inspath.last/clean/custom."* "$inspath/clean/" 2> /dev/null
			eout "{update} completed update v$lmd_version ${installed_hash:0:6} => v$upstreamver_readable, running signature updates..." 1
			_lmd_elog_event "$ELOG_EVT_UPDATE_COMPLETED" "info" "version update completed" "action=lmdup" "from=$lmd_version" "to=$upstreamver_readable"
			$inspath/maldet --update 1
			eout "{update} update and config import completed" 1
		else
			eout "{update} could not download ${lmd_current_tgzfile}, please try again later." 1
			_lmd_elog_event "$ELOG_EVT_UPDATE_FAILED" "error" "version update failed" "action=lmdup" "reason=download_failed"
			cd "$inspath" ; command rm -rf "$tmpwd"
			clean_exit
			exit 1
		fi
	fi
	_grf_cleanup
	cd "$inspath" ; command rm -rf "$tmpwd"
}

sigup() {
	eout "{sigup} performing signature update check..." 1

	# Serialize with --cron-sigup to prevent racing on $sigdir
	local _sigup_lockfile="$tmpdir/.sigup.lock"
	if command -v flock >/dev/null 2>&1; then
		exec 8>"$_sigup_lockfile"
		if ! flock -n 8; then
			eout "{sigup} another signature update is running, skipping" 1
			return 0
		fi
	fi

	tmpwd=$(mktemp -d "$tmpdir/.sigup.XXXXXX")
	chmod 700 "$tmpwd"

	import_user_sigs

	if [ -z "$sig_version" ]; then
		eout "{sigup} could not determine signature version" 1
		sig_version=0
	else
		eout "{sigup} local signature set is version $sig_version" 1
	fi

	get_remote_file "$sig_version_url" "sigup" "1"
	upstream_sigver="$return_file"

	if [ ! -f "$upstream_sigver" ] || [ ! -s "$upstream_sigver" ]; then
		eout "{sigup} could not download signature data from server, please try again later." 1
		_lmd_elog_event "$ELOG_EVT_UPDATE_FAILED" "error" "signature update failed" "action=sigup" "reason=version_check_failed"
		_grf_cleanup
		clean_exit
		exit 1
	else
		nver=$(cat "$upstream_sigver")
	fi

	if [ ! -f "$sig_md5_file" ] || [ ! -f "$sig_hex_file" ]; then
		sig_version=2012010100000
		eout "{sigup} signature files missing or corrupted, forcing update..." 1
	else
		_count_signatures "$sig_md5_file" "$sig_hex_file"
		if [ "$md5_sigs" -lt "1000" ] || [ "$hex_sigs" -lt "1000" ]; then
			sig_version=2012010100000
			eout "{sigup} signature files corrupted, forcing update..." 1
		fi
	fi
	if [ "$sigup_force" ]; then
		sig_version=2012010100000
		eout "{sigup} signature update with --force requested, forcing update..." 1
	fi

	if [ "$nver" != "$sig_version" ]; then
		cd "$tmpwd/" || { eout "{sigup} failed to cd to temp dir, aborting sigup" 1; command rm -rf "$tmpwd"; exit 1; }
		tar=$(command -v tar 2> /dev/null)
		eout "{sigup} new signature set $nver available" 1
		_lmd_elog_event "$ELOG_EVT_UPDATE_STARTED" "info" "signature update started" "action=sigup" "version=$nver"

		eout "{sigup} downloading $sig_sigpack_url" 1
		get_remote_file "$sig_sigpack_url" "sigup" "1" "$tmpwd/maldet-sigpack.tgz"

		eout "{sigup} downloading $sig_clpack_url" 1
		get_remote_file "$sig_clpack_url" "sigup" "1" "$tmpwd/maldet-clean.tgz"

		if ! _verify_download "$tmpwd/maldet-sigpack.tgz" \
				"$sig_sigpack_url" "sigup" "$tmpwd/maldet-sigpack.tgz"; then
			sigpackfail=1
		else
			if [ -f "$tmpwd/maldet-sigpack.tgz" ] && [ -s "$tmpwd/maldet-sigpack.tgz" ]; then
				tar --no-same-owner -xzf "$tmpwd/maldet-sigpack.tgz" 2> /dev/null
				if [ -d "$tmpwd/sigs" ]; then
					mkdir -p "$sigdir.old" 2> /dev/null
					command rm -f "$sigdir.old"/* 2> /dev/null
					command cp -f "$sigdir"/* "$sigdir.old"/ 2> /dev/null
					command cp -f "$tmpwd"/sigs/* "$sigdir" 2> /dev/null
					# Guard: write downloaded version to ver file in case tarball
					# contents are out of sync with the CDN version endpoint
					if [ -n "$nver" ]; then
						echo "$nver" > "$sig_version_file"
					fi
					eout "{sigup} unpacked and installed maldet-sigpack.tgz" 1
					local _clamav_ok=0 _clamav_fail=0
					for _cpath in $clamav_paths; do
						if clamav_linksigs "$_cpath"; then
							_clamav_ok=$(( _clamav_ok + 1 ))
						else
							_clamav_fail=$(( _clamav_fail + 1 ))
						fi
					done
					if [ "$_clamav_ok" -gt 0 ]; then
						killall -SIGUSR2 clamd 2>/dev/null
						if [ "$_clamav_fail" -gt 0 ]; then
							eout "{sigup} clamav signature deployment: $_clamav_fail path(s) failed validation" 1
						fi
					else
						eout "{sigup} clamav signature validation failed for all paths — clamd reload skipped" 1
					fi
				else
					eout "{sigup} something went wrong unpacking $sig_sigpack_url, aborting!" 1
					sigpackfail=1
				fi
			else
				eout "{sigup} could not download $sig_sigpack_url" 1
				sigpackfail=1
			fi
		fi

		if ! _verify_download "$tmpwd/maldet-clean.tgz" \
				"$sig_clpack_url" "sigup" "$tmpwd/maldet-clean.tgz"; then
			clpackfail=1
		else
			if [ -f "$tmpwd/maldet-clean.tgz" ] && [ -s "$tmpwd/maldet-clean.tgz" ]; then
				tar --no-same-owner -xzf "$tmpwd/maldet-clean.tgz"
				if [ -d "$tmpwd/clean" ]; then
					command cp -f "$tmpwd"/clean/* "$cldir"
					eout "{sigup} unpacked and installed maldet-clean.tgz" 1
				else
					eout "{sigup} clean rules archive contained no data" 1
				fi
			else
				eout "{sigup} error handling $sig_clpack_url, file is either missing or zero sized, aborting!" 1
				clpackfail=1
			fi
		fi

		if [ "$sigpackfail" ]; then
			_lmd_elog_event "$ELOG_EVT_UPDATE_FAILED" "error" "signature update failed" "action=sigup" "reason=sigpack_failed"
			cd "$inspath"
			command rm -rf "$tmpwd"
			clean_exit
			exit 1
		else
			eout "{sigup} signature set update completed" 1

			_resolve_clamscan
			_resolve_yara
			_count_signatures "$sig_md5_file" "$sig_hex_file"
			_lmd_elog_event "$ELOG_EVT_UPDATE_COMPLETED" "info" "signature update completed" "action=sigup" "version=$nver" "sigs=$tot_sigs"
			eout "{sigup} $(_format_number $tot_sigs) signatures ($(_format_number $hash_sigs) $_hash_label | $(_format_number $hex_sigs) HEX | $(_format_number $csig_sigs) CSIG | $(_format_number $yara_sigs) $_yara_label | $(_format_number $user_sigs) USER)" 1
		fi
		cd "$inspath"
		command rm -rf "$tmpwd"
	else
		eout "{sigup} latest signature set already installed" 1
		cd "$inspath"
		command rm -rf "$tmpwd"
	fi
	_grf_cleanup
}
