#!/bin/bash
# alert_lib.sh — shared library for multi-channel transactional alerting
# Provides channel registry, template engine, MIME builder, and multi-channel
# delivery (email, Slack, Telegram, Discord).
# Consumed by BFD and LMD via source inclusion.
#
# Copyright (C) 2002-2026 R-fx Networks <proj@rfxn.com>
#                         Ryan MacDonald <ryan@rfxn.com>
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# Source guard — prevent double-sourcing
[[ -n "${_ALERT_LIB_LOADED:-}" ]] && return 0 2>/dev/null
_ALERT_LIB_LOADED=1

# shellcheck disable=SC2034
ALERT_LIB_VERSION="1.0.7"

# Parallel indexed arrays (not declare -A) — sourcing from inside a function
# (BATS load, wrapper fns) would otherwise create locals instead of globals.
_ALERT_CHANNEL_NAMES=()
_ALERT_CHANNEL_HANDLERS=()
_ALERT_CHANNEL_ENABLED=()

ALERT_CURL_TIMEOUT="${ALERT_CURL_TIMEOUT:-30}"
ALERT_CURL_MAX_TIME="${ALERT_CURL_MAX_TIME:-120}"
ALERT_TMPDIR="${ALERT_TMPDIR:-${TMPDIR:-/tmp}}"

# _alert_channel_find name — locate channel index by name
# Sets _ALERT_CHANNEL_IDX to avoid subshell fork (pattern shared with _ALERT_TPL_RESOLVED).
_alert_channel_find() {
	local name="$1"
	local i
	_ALERT_CHANNEL_IDX=-1
	for i in "${!_ALERT_CHANNEL_NAMES[@]}"; do
		if [ "${_ALERT_CHANNEL_NAMES[$i]}" = "$name" ]; then
			_ALERT_CHANNEL_IDX=$i
			return 0
		fi
	done
	return 1
}

# alert_channel_register name handler_fn — register a delivery channel (starts disabled)
alert_channel_register() {
	local name="$1" handler_fn="$2"
	if [ -z "$name" ]; then
		echo "alert_lib: channel name cannot be empty." >&2
		return 1
	fi
	if [ -z "$handler_fn" ]; then
		echo "alert_lib: handler function cannot be empty for channel '$name'." >&2
		return 1
	fi
	if _alert_channel_find "$name"; then
		echo "alert_lib: channel '$name' already registered." >&2
		return 1
	fi
	_ALERT_CHANNEL_NAMES+=("$name")
	_ALERT_CHANNEL_HANDLERS+=("$handler_fn")
	_ALERT_CHANNEL_ENABLED+=("0")
	return 0
}

# alert_channel_enable name — mark channel as active
alert_channel_enable() {
	local name="$1"
	if ! _alert_channel_find "$name"; then
		echo "alert_lib: channel '$name' not registered." >&2
		return 1
	fi
	_ALERT_CHANNEL_ENABLED[_ALERT_CHANNEL_IDX]=1
	return 0
}

# alert_channel_disable name — mark channel as inactive
alert_channel_disable() {
	local name="$1"
	if ! _alert_channel_find "$name"; then
		echo "alert_lib: channel '$name' not registered." >&2
		return 1
	fi
	_ALERT_CHANNEL_ENABLED[_ALERT_CHANNEL_IDX]=0
	return 0
}

# alert_channel_enabled name — check if channel is active
alert_channel_enabled() {
	local name="$1"
	if ! _alert_channel_find "$name"; then
		return 1
	fi
	[ "${_ALERT_CHANNEL_ENABLED[_ALERT_CHANNEL_IDX]}" = "1" ]
}

# _alert_tpl_render template_file — render {{VAR}} tokens from environ to stdout
# Single-pass awk via ENVIRON; unknown tokens become empty. No eval, mawk-compatible.
_alert_tpl_render() {
	local template_file="$1"
	if [ ! -f "$template_file" ]; then
		return 1
	fi
	awk '{
		line = $0
		while (match(line, /\{\{[A-Z_][A-Z0-9_]*\}\}/)) {
			token = substr(line, RSTART + 2, RLENGTH - 4)
			val = ENVIRON[token]
			line = substr(line, 1, RSTART - 1) val substr(line, RSTART + RLENGTH)
		}
		print line
	}' "$template_file"
}

# _alert_tpl_resolve template_dir template_name — resolve with custom.d/ override
# Sets _ALERT_TPL_RESOLVED to avoid subshell fork from stdout return.
_alert_tpl_resolve() {
	local template_dir="$1" template_name="$2"
	_ALERT_TPL_RESOLVED="$template_dir/$template_name"
	if [ -f "$template_dir/custom.d/$template_name" ]; then
		_ALERT_TPL_RESOLVED="$template_dir/custom.d/$template_name"
	fi
}

# _alert_html_escape str — escape & < > " ' for safe HTML embedding
# Uses sed (not ${var//}) because bash 5.2 treats & as a backreference in replacements.
_alert_html_escape() {
	if [ -z "$1" ]; then
		printf ''
		return 0
	fi
	printf '%s' "$1" | sed \
		-e 's/&/\&amp;/g' \
		-e 's/</\&lt;/g' \
		-e 's/>/\&gt;/g' \
		-e 's/"/\&quot;/g' \
		-e "s/'/\\&#39;/g"
}

# _alert_json_escape str — escape \ " \n \t \r for JSON string embedding
_alert_json_escape() {
	local s="$1"
	s="${s//\\/\\\\}"
	s="${s//\"/\\\"}"
	s="${s//$'\n'/\\n}"
	s="${s//$'\t'/\\t}"
	s="${s//$'\r'/\\r}"
	printf '%s' "$s"
}

# _alert_telegram_escape str — escape MarkdownV2 special chars
# Character list per https://core.telegram.org/bots/api#markdownv2-style
_alert_telegram_escape() {
	if [ -z "$1" ]; then
		printf ''
		return 0
	fi
	# BRE character class layout: ] first (literal), [ next, remaining chars, - last (literal).
	printf '%s' "$1" | sed \
		-e 's/\\/\\\\/g' \
		-e 's/[][_*()~`>#+=|{}.!-]/\\&/g'
}

# _alert_slack_escape str — escape & < > for Slack mrkdwn
# Uses sed (not ${var//}) because bash 5.2 treats & as a backreference in replacements.
_alert_slack_escape() {
	if [ -z "$1" ]; then
		printf ''
		return 0
	fi
	printf '%s' "$1" | sed \
		-e 's/&/\&amp;/g' \
		-e 's/</\&lt;/g' \
		-e 's/>/\&gt;/g'
}

# _alert_validate_url url — check for http:// or https:// scheme
_alert_validate_url() {
	case "${1:-}" in
		http://*|https://*) return 0 ;;
		*) return 1 ;;
	esac
}

# _alert_redact_url url — strip tokens from Slack/Discord webhook URLs for logging
_alert_redact_url() {
	local url="$1"
	if [[ "$url" == *"hooks.slack.com/services/"* ]]; then
		printf '%s' "${url%/*}/[REDACTED]"
	elif [[ "$url" == *"discord.com/api/webhooks/"* ]] || [[ "$url" == *"discordapp.com/api/webhooks/"* ]]; then
		printf '%s' "${url%/*}/[REDACTED]"
	else
		printf '%s' "$url"
	fi
}

# _alert_curl_post url [curl_flags...] — HTTP POST via curl with standard timeouts
# Caller supplies -d/-H/-F; stdout carries the response body for capture via $().
_alert_curl_post() {
	local url="$1"
	shift
	local curl_bin
	curl_bin=$(command -v curl 2>/dev/null || true)
	if [ -z "$curl_bin" ]; then
		echo "alert_lib: curl not found, cannot POST to $(_alert_redact_url "$url")." >&2
		return 1
	fi
	local rc=0 curl_stderr
	curl_stderr=$(mktemp "${ALERT_TMPDIR}/alert_curl_err.XXXXXX")
	"$curl_bin" -s --connect-timeout "$ALERT_CURL_TIMEOUT" --max-time "$ALERT_CURL_MAX_TIME" \
		-X POST "$url" "$@" 2>"$curl_stderr" || rc=$?
	if [ "$rc" -ne 0 ]; then
		local _err_detail
		_err_detail=$(head -5 "$curl_stderr" | tr '\n' ' ')
		echo "alert_lib: POST to $(_alert_redact_url "$url") failed (curl exit $rc): $_err_detail" >&2
		command rm -f "$curl_stderr"
		return 1
	fi
	command rm -f "$curl_stderr"
	return 0
}

# _alert_build_mime text_body html_body — write multipart/alternative MIME to stdout
# Caller must emit Subject/To/From headers before this output.
_alert_build_mime() {
	local text_body="$1" html_body="$2"
	local boundary
	# /dev/urandom for unpredictable boundary; PID fallback is sufficient per-message
	boundary="ALERT_$(date +%s)_$(tr -dc 'A-Za-z0-9' < /dev/urandom 2>/dev/null | head -c 8 || echo "$$")"

	echo "MIME-Version: 1.0"
	echo "Content-Type: multipart/alternative; boundary=\"$boundary\""
	echo ""
	echo "--$boundary"
	echo "Content-Type: text/plain; charset=UTF-8"
	echo "Content-Transfer-Encoding: 8bit"
	echo ""
	echo "$text_body"
	echo ""
	echo "--$boundary"
	echo "Content-Type: text/html; charset=UTF-8"
	echo "Content-Transfer-Encoding: base64"
	echo ""
	# base64 wraps at 76 chars, satisfying RFC 5321 998-char line limit
	printf '%s\n' "$html_body" | base64
	echo ""
	echo "--${boundary}--"
}

# _alert_email_local recip subject text_file html_file format — send via mail/sendmail
# format: text, html, or both.
_alert_email_local() {
	local recip="$1" subject="$2" text_file="$3" html_file="$4" format="${5:-text}"
	local from="${ALERT_SMTP_FROM:-root@$(hostname -f 2>/dev/null || hostname)}"
	# Defense-in-depth: strip CR/LF from all values used in email headers
	recip="${recip//$'\r'/}"
	recip="${recip//$'\n'/}"
	subject="${subject//$'\r'/}"
	subject="${subject//$'\n'/}"
	from="${from//$'\r'/}"
	from="${from//$'\n'/}"
	local reply_to="${ALERT_EMAIL_REPLY_TO:-}"
	reply_to="${reply_to//$'\r'/}"
	reply_to="${reply_to//$'\n'/}"

	local sendmail_bin mail_bin
	sendmail_bin=$(command -v sendmail 2>/dev/null || true)
	mail_bin=$(command -v mail 2>/dev/null || true)

	case "$format" in
		text)
			if [ -n "$mail_bin" ]; then
				"$mail_bin" -s "$subject" "$recip" < "$text_file"
				return $?
			fi
			# mail not available — fall back to sendmail
			if [ -n "$sendmail_bin" ]; then
				local _tmpmail
				_tmpmail=$(mktemp "${ALERT_TMPDIR}/alert_text_msg.XXXXXX")
				{
					echo "From: $from"
					echo "To: $recip"
					echo "Subject: $subject"
					if [ -n "$reply_to" ]; then
						echo "Reply-To: $reply_to"
					fi
					echo ""
					cat "$text_file"
				} > "$_tmpmail"
				"$sendmail_bin" -t -oi < "$_tmpmail"
				local _rc=$?
				command rm -f "$_tmpmail"
				return $_rc
			fi
			echo "alert_lib: mail binary not found, cannot send alert to $recip." >&2
			return 1
			;;
		html)
			if [ -n "$sendmail_bin" ]; then
				{
					echo "From: $from"
					echo "To: $recip"
					echo "Subject: $subject"
					if [ -n "$reply_to" ]; then
						echo "Reply-To: $reply_to"
					fi
					echo "Content-Type: text/html; charset=UTF-8"
					echo "Content-Transfer-Encoding: base64"
					echo ""
					# base64 wraps at 76 chars, satisfying RFC 5321 998-char line limit
					base64 < "$html_file"
				} | "$sendmail_bin" -t -oi
				return $?
			fi
			# sendmail not available — fall back to text via mail
			echo "alert_lib: warning: sendmail not found, falling back to text-only alert for $recip." >&2
			if [ -z "$mail_bin" ]; then
				echo "alert_lib: mail binary not found, cannot send alert to $recip." >&2
				return 1
			fi
			"$mail_bin" -s "$subject" "$recip" < "$text_file"
			return $?
			;;
		both)
			if [ -n "$sendmail_bin" ]; then
				local text_body html_body
				text_body=$(cat "$text_file")
				html_body=$(cat "$html_file")
				{
					echo "From: $from"
					echo "To: $recip"
					echo "Subject: $subject"
					if [ -n "$reply_to" ]; then
						echo "Reply-To: $reply_to"
					fi
					_alert_build_mime "$text_body" "$html_body"
				} | "$sendmail_bin" -t -oi
				return $?
			fi
			# sendmail not available — fall back to text via mail
			echo "alert_lib: warning: sendmail not found, falling back to text-only alert for $recip." >&2
			if [ -z "$mail_bin" ]; then
				echo "alert_lib: mail binary not found, cannot send alert to $recip." >&2
				return 1
			fi
			"$mail_bin" -s "$subject" "$recip" < "$text_file"
			return $?
			;;
		*)
			echo "alert_lib: unknown format '$format', cannot send alert." >&2
			return 1
			;;
	esac
}

# _alert_email_relay recip subject msg_file — send via authenticated SMTP relay
# msg_file must be a complete RFC 822 message. TLS: smtps:// and :587 require it,
# :25 stays plaintext (internal relays). Credentials optional for auth-free relays.
_alert_email_relay() {
	local recip="$1" subject="$2" msg_file="$3"

	if [ -z "${ALERT_SMTP_FROM:-}" ]; then
		echo "alert_lib: ALERT_SMTP_FROM not set, cannot send relay alert to $recip." >&2
		return 1
	fi
	local curl_bin
	curl_bin=$(command -v curl 2>/dev/null || true)
	if [ -z "$curl_bin" ]; then
		echo "alert_lib: curl not found, cannot send relay alert to $recip." >&2
		return 1
	fi

	local -a curl_args=("-s" "--url" "$ALERT_SMTP_RELAY")

	case "$ALERT_SMTP_RELAY" in
		smtps://*|smtp://*:587|smtp://*:587/*) curl_args+=("--ssl-reqd") ;;
		smtp://*:25|smtp://*:25/*) ;;  # plain — no TLS for internal relays
		*) curl_args+=("--ssl-reqd") ;;  # default: require TLS for safety
	esac

	curl_args+=("--mail-from" "$ALERT_SMTP_FROM" "--mail-rcpt" "$recip")

	# -K config file keeps credentials out of process listing (same as _alert_telegram_api)
	local smtp_cfg=""
	if [ -n "${ALERT_SMTP_USER:-}" ] && [ -n "${ALERT_SMTP_PASS:-}" ]; then
		smtp_cfg=$(mktemp "${ALERT_TMPDIR}/alert_smtp_auth.XXXXXX")
		chmod 600 "$smtp_cfg"
		printf 'user = "%s:%s"\n' "$ALERT_SMTP_USER" "$ALERT_SMTP_PASS" > "$smtp_cfg"
		curl_args+=("-K" "$smtp_cfg")
	fi

	curl_args+=("--upload-file" "$msg_file")

	local rc=0 curl_stderr
	curl_stderr=$(mktemp "${ALERT_TMPDIR}/alert_curl_err.XXXXXX")
	"$curl_bin" "${curl_args[@]}" 2>"$curl_stderr" || rc=$?
	if [ "$rc" -ne 0 ]; then
		local _err_detail
		_err_detail=$(head -5 "$curl_stderr" | tr '\n' ' ')
		echo "alert_lib: SMTP relay to $recip failed (curl exit $rc): $_err_detail" >&2
		command rm -f "$curl_stderr" "$smtp_cfg"
		return 1
	fi
	command rm -f "$curl_stderr" "$smtp_cfg"
	return 0
}

# _alert_deliver_email recip subject text_file html_file format — router
# ALERT_SMTP_RELAY set: relay path (always builds full multipart/alternative,
# format parameter ignored — _alert_build_mime requires both parts).
# Otherwise: local MTA path via _alert_email_local (format applies).
_alert_deliver_email() {
	local recip="$1" subject="$2" text_file="$3" html_file="$4" format="${5:-text}"

	if [ -z "$recip" ]; then
		echo "alert_lib: email recipient is required." >&2
		return 1
	fi

	# Strip CR/LF to prevent email header injection
	subject="${subject//$'\r'/}"
	subject="${subject//$'\n'/}"

	if [ -n "${ALERT_SMTP_RELAY:-}" ]; then
		local from="${ALERT_SMTP_FROM:-root@$(hostname -f 2>/dev/null || hostname)}"
		# Defense-in-depth: strip CR/LF from all header values to prevent injection
		recip="${recip//$'\r'/}"
		recip="${recip//$'\n'/}"
		from="${from//$'\r'/}"
		from="${from//$'\n'/}"
		local reply_to="${ALERT_EMAIL_REPLY_TO:-}"
		reply_to="${reply_to//$'\r'/}"
		reply_to="${reply_to//$'\n'/}"
		local text_body html_body
		text_body=$(cat "$text_file")
		html_body=$(cat "$html_file")
		local msg_file
		msg_file=$(mktemp "${ALERT_TMPDIR}/alert_relay_msg.XXXXXX")
		{
			echo "From: $from"
			echo "To: $recip"
			echo "Subject: $subject"
			if [ -n "$reply_to" ]; then
				echo "Reply-To: $reply_to"
			fi
			echo "Date: $(date -R 2>/dev/null || date)"
			_alert_build_mime "$text_body" "$html_body"
		} > "$msg_file"
		_alert_email_relay "$recip" "$subject" "$msg_file"
		local rc=$?
		command rm -f "$msg_file"
		return $rc
	fi

	_alert_email_local "$recip" "$subject" "$text_file" "$html_file" "$format"
}

# _alert_handle_email subject text_file html_file [attachment] — email channel handler
# Reads ALERT_EMAIL_TO (default: root) and ALERT_EMAIL_FORMAT (default: text).
_alert_handle_email() {
	local subject="$1" text_file="$2" html_file="$3"
	local recip="${ALERT_EMAIL_TO:-root}"
	local format="${ALERT_EMAIL_FORMAT:-text}"
	_alert_deliver_email "$recip" "$subject" "$text_file" "$html_file" "$format"
}

# _alert_slack_webhook payload_file webhook_url — POST JSON to Slack incoming webhook
_alert_slack_webhook() {
	local payload_file="$1" webhook_url="$2"
	if [ -z "$webhook_url" ] || ! _alert_validate_url "$webhook_url"; then
		echo "alert_lib: invalid or empty Slack webhook URL." >&2
		return 1
	fi
	local response
	response=$(_alert_curl_post "$webhook_url" \
		-H "Content-Type: application/json" -d @"$payload_file") || return 1
	# Slack webhooks return "ok" on success, error string on failure
	if [ "$response" != "ok" ]; then
		echo "alert_lib: Slack webhook error: $response" >&2
		return 1
	fi
	return 0
}

# _alert_slack_post_message payload_file token channel — POST to chat.postMessage API
# Token written to chmod 600 config and passed via curl -K to keep it out of /proc/PID/cmdline.
_alert_slack_post_message() {
	local payload_file="$1" token="$2" channel="$3"
	if [ -z "$token" ]; then
		echo "alert_lib: Slack token is required for bot mode." >&2
		return 1
	fi
	if [ -z "$channel" ]; then
		echo "alert_lib: Slack channel is required for bot mode." >&2
		return 1
	fi
	if [ ! -f "$payload_file" ]; then
		echo "alert_lib: payload file not found: ${payload_file:-<empty>}" >&2
		return 1
	fi
	# awk (not sed) for channel injection: sed s/// would collide with / or & in channel
	local modified_payload escaped_channel
	modified_payload=$(mktemp "${ALERT_TMPDIR}/alert_slack_msg.XXXXXX")
	escaped_channel=$(_alert_json_escape "$channel")
	ch="$escaped_channel" awk 'NR==1 && /^\{/ { print "{\"channel\":\"" ENVIRON["ch"] "\"," substr($0,2); next } { print }' \
		"$payload_file" > "$modified_payload"
	local auth_cfg
	auth_cfg=$(mktemp "${ALERT_TMPDIR}/alert_sl_auth.XXXXXX")
	chmod 600 "$auth_cfg"
	printf 'header = "Authorization: Bearer %s"\n' "$token" > "$auth_cfg"
	local response
	response=$(_alert_curl_post "https://slack.com/api/chat.postMessage" \
		-K "$auth_cfg" \
		-H "Content-Type: application/json" \
		-d @"$modified_payload") || { command rm -f "$modified_payload" "$auth_cfg"; return 1; }
	command rm -f "$modified_payload" "$auth_cfg"
	case "$response" in
		*'"ok":true'*) return 0 ;;
	esac
	local api_err
	api_err=$(printf '%s' "$response" | sed -n 's/.*"error" *: *"\([^"]*\)".*/\1/p')
	echo "alert_lib: Slack chat.postMessage error${api_err:+: $api_err}" >&2
	return 1
}

# _alert_slack_upload file_path title token channels — 3-step Slack file upload
# Steps: files.getUploadURLExternal → POST to upload_url → files.completeUploadExternal.
# Token written to chmod 600 config and passed via curl -K to keep it out of /proc/PID/cmdline.
_alert_slack_upload() {
	local file_path="$1" title="$2" token="$3" channels="$4"
	if [ ! -f "$file_path" ]; then
		echo "alert_lib: file not found: $file_path" >&2
		return 1
	fi
	if [ -z "$token" ]; then
		echo "alert_lib: Slack token is required for file upload." >&2
		return 1
	fi
	local fsize filename
	fsize=$(wc -c < "$file_path")
	fsize="${fsize##* }"  # trim whitespace (some wc implementations pad)
	filename="${file_path##*/}"

	local auth_cfg
	auth_cfg=$(mktemp "${ALERT_TMPDIR}/alert_sl_auth.XXXXXX")
	chmod 600 "$auth_cfg"
	printf 'header = "Authorization: Bearer %s"\n' "$token" > "$auth_cfg"

	# Step 1: get upload URL
	local url_response upload_url file_id
	url_response=$(_alert_curl_post "https://slack.com/api/files.getUploadURLExternal" \
		-K "$auth_cfg" \
		--data-urlencode "filename=$filename" \
		-d "length=$fsize") || { command rm -f "$auth_cfg"; return 1; }
	case "$url_response" in
		*'"ok":true'*) ;;
		*)
			local api_err
			api_err=$(printf '%s' "$url_response" | sed -n 's/.*"error" *: *"\([^"]*\)".*/\1/p')
			echo "alert_lib: Slack getUploadURLExternal error${api_err:+: $api_err}" >&2
			command rm -f "$auth_cfg"
			return 1
			;;
	esac
	upload_url=$(printf '%s' "$url_response" | sed -n 's/.*"upload_url" *: *"\([^"]*\)".*/\1/p')
	file_id=$(printf '%s' "$url_response" | sed -n 's/.*"file_id" *: *"\([^"]*\)".*/\1/p')

	# Defense-in-depth: reject non-https schemes (http, file, ftp, ...).
	# Case-insensitive match — ${var,,} is prohibited on bash 4.1 floor.
	case "$upload_url" in
		[hH][tT][tT][pP][sS]://*)
			;;
		*)
			echo "alert_lib: Slack upload URL rejected (not https): ${upload_url:-(empty)}" >&2
			command rm -f "$auth_cfg"
			return 1
			;;
	esac

	# Step 2: upload file content to presigned URL (no auth header needed)
	_alert_curl_post "$upload_url" -F "file=@$file_path" > /dev/null || {
		echo "alert_lib: Slack file upload to presigned URL failed." >&2
		command rm -f "$auth_cfg"
		return 1
	}

	# Step 3: complete upload and share to channels
	local escaped_title escaped_channels escaped_file_id complete_response
	escaped_title=$(_alert_json_escape "$title")
	escaped_channels=$(_alert_json_escape "$channels")
	escaped_file_id=$(_alert_json_escape "$file_id")
	complete_response=$(_alert_curl_post "https://slack.com/api/files.completeUploadExternal" \
		-K "$auth_cfg" \
		-H "Content-Type: application/json" \
		-d "{\"files\":[{\"id\":\"$escaped_file_id\",\"title\":\"$escaped_title\"}],\"channels\":\"$escaped_channels\"}") || { command rm -f "$auth_cfg"; return 1; }
	command rm -f "$auth_cfg"
	case "$complete_response" in
		*'"ok":true'*) return 0 ;;
	esac
	local complete_err
	complete_err=$(printf '%s' "$complete_response" | sed -n 's/.*"error" *: *"\([^"]*\)".*/\1/p')
	echo "alert_lib: Slack completeUploadExternal error${complete_err:+: $complete_err}" >&2
	return 1
}

# _alert_deliver_slack payload_file [attachment_file] — route Slack delivery
# ALERT_SLACK_MODE: webhook (ALERT_SLACK_WEBHOOK_URL) or bot (ALERT_SLACK_TOKEN + ALERT_SLACK_CHANNEL).
_alert_deliver_slack() {
	local payload_file="$1" attachment="${2:-}"
	local mode="${ALERT_SLACK_MODE:-webhook}"

	case "$mode" in
		webhook)
			if [ -z "${ALERT_SLACK_WEBHOOK_URL:-}" ]; then
				echo "alert_lib: ALERT_SLACK_WEBHOOK_URL not set." >&2
				return 1
			fi
			if [ -n "$attachment" ]; then
				echo "alert_lib: warning: Slack webhooks cannot upload files, attachment skipped." >&2
			fi
			_alert_slack_webhook "$payload_file" "$ALERT_SLACK_WEBHOOK_URL"
			;;
		bot)
			if [ -z "${ALERT_SLACK_TOKEN:-}" ]; then
				echo "alert_lib: ALERT_SLACK_TOKEN not set." >&2
				return 1
			fi
			if [ -z "${ALERT_SLACK_CHANNEL:-}" ]; then
				echo "alert_lib: ALERT_SLACK_CHANNEL not set." >&2
				return 1
			fi
			_alert_slack_post_message "$payload_file" "$ALERT_SLACK_TOKEN" "$ALERT_SLACK_CHANNEL" || return 1
			if [ -n "$attachment" ] && [ -f "$attachment" ]; then
				_alert_slack_upload "$attachment" "${attachment##*/}" "$ALERT_SLACK_TOKEN" "$ALERT_SLACK_CHANNEL" || return 1
			fi
			return 0
			;;
		*)
			echo "alert_lib: unknown ALERT_SLACK_MODE '$mode'." >&2
			return 1
			;;
	esac
}

# _alert_handle_slack subject text_file html_file [attachment] — Slack channel handler
# text_file is the rendered JSON payload; subject and html_file are ignored (baked in).
_alert_handle_slack() {
	local text_file="$2" attachment="${4:-}"
	_alert_deliver_slack "$text_file" "$attachment"
}

# _alert_telegram_api endpoint bot_token [curl_flags...] — shared Bot API helper
# curl -K config file (chmod 600, deleted after curl) keeps bot token out of /proc/PID/cmdline.
_alert_telegram_api() {
	local endpoint="$1" bot_token="$2"
	shift 2
	local curl_bin
	curl_bin=$(command -v curl 2>/dev/null || true)
	if [ -z "$curl_bin" ]; then
		echo "alert_lib: curl not found, cannot call Telegram API." >&2
		return 1
	fi
	local cfg
	cfg=$(mktemp "${ALERT_TMPDIR}/alert_tg_curl.XXXXXX")
	chmod 600 "$cfg"
	printf 'url = "https://api.telegram.org/bot%s/%s"\n' "$bot_token" "$endpoint" > "$cfg"
	local rc=0 response
	# 2>/dev/null on curl: -K config file interacts with stderr capture;
	# API response JSON contains all diagnostic info needed
	response=$("$curl_bin" -s --connect-timeout "$ALERT_CURL_TIMEOUT" \
		--max-time "$ALERT_CURL_MAX_TIME" -K "$cfg" "$@" 2>/dev/null) || rc=$?
	command rm -f "$cfg"
	if [ "$rc" -ne 0 ]; then
		echo "alert_lib: Telegram API curl failed (exit $rc)." >&2
		return 1
	fi
	case "$response" in
		*'"ok":true'*)
			printf '%s' "$response"
			return 0
			;;
	esac
	local api_err
	api_err=$(printf '%s' "$response" | sed -n 's/.*"description" *: *"\([^"]*\)".*/\1/p')
	echo "alert_lib: Telegram API error${api_err:+: $api_err}" >&2
	return 1
}

# _alert_telegram_message text bot_token chat_id — send text via sendMessage (MarkdownV2)
_alert_telegram_message() {
	local text="$1" bot_token="$2" chat_id="$3"
	if [ -z "$bot_token" ]; then
		echo "alert_lib: Telegram bot token is required." >&2
		return 1
	fi
	if [ -z "$chat_id" ]; then
		echo "alert_lib: Telegram chat_id is required." >&2
		return 1
	fi
	if [ -z "$text" ]; then
		echo "alert_lib: Telegram message text cannot be empty." >&2
		return 1
	fi
	_alert_telegram_api "sendMessage" "$bot_token" \
		-F "chat_id=$chat_id" \
		-F "text=$text" \
		-F "parse_mode=MarkdownV2" > /dev/null
}

# _alert_telegram_document file_path caption bot_token chat_id — send file via sendDocument
_alert_telegram_document() {
	local file_path="$1" caption="$2" bot_token="$3" chat_id="$4"
	if [ ! -f "$file_path" ]; then
		echo "alert_lib: file not found: $file_path" >&2
		return 1
	fi
	if [ -z "$bot_token" ]; then
		echo "alert_lib: Telegram bot token is required." >&2
		return 1
	fi
	if [ -z "$chat_id" ]; then
		echo "alert_lib: Telegram chat_id is required." >&2
		return 1
	fi
	if [ -n "$caption" ]; then
		_alert_telegram_api "sendDocument" "$bot_token" \
			-F "chat_id=$chat_id" \
			-F "document=@$file_path" \
			-F "caption=$caption" > /dev/null
	else
		_alert_telegram_api "sendDocument" "$bot_token" \
			-F "chat_id=$chat_id" \
			-F "document=@$file_path" > /dev/null
	fi
}

# _alert_deliver_telegram payload_file [attachment_file] — route Telegram delivery
# Message sent first; attachment only on message success. Missing attachment silently skipped.
_alert_deliver_telegram() {
	local payload_file="$1" attachment="${2:-}"
	if [ -z "${ALERT_TELEGRAM_BOT_TOKEN:-}" ]; then
		echo "alert_lib: ALERT_TELEGRAM_BOT_TOKEN not set." >&2
		return 1
	fi
	if [ -z "${ALERT_TELEGRAM_CHAT_ID:-}" ]; then
		echo "alert_lib: ALERT_TELEGRAM_CHAT_ID not set." >&2
		return 1
	fi
	local text
	text=$(cat "$payload_file")
	_alert_telegram_message "$text" "$ALERT_TELEGRAM_BOT_TOKEN" "$ALERT_TELEGRAM_CHAT_ID" || return 1
	if [ -n "$attachment" ] && [ -f "$attachment" ]; then
		_alert_telegram_document "$attachment" "" "$ALERT_TELEGRAM_BOT_TOKEN" "$ALERT_TELEGRAM_CHAT_ID" || return 1
	fi
	return 0
}

# _alert_handle_telegram subject text_file html_file [attachment] — Telegram channel handler
# text_file is the payload; subject and html_file are ignored (baked in).
_alert_handle_telegram() {
	local text_file="$2" attachment="${4:-}"
	_alert_deliver_telegram "$text_file" "$attachment"
}

# _alert_discord_webhook payload_file webhook_url — POST JSON to Discord webhook
# Discord returns HTTP 204 with empty body on success (no ?wait=true).
_alert_discord_webhook() {
	local payload_file="$1" webhook_url="$2"
	if [ -z "$webhook_url" ] || ! _alert_validate_url "$webhook_url"; then
		echo "alert_lib: invalid or empty Discord webhook URL." >&2
		return 1
	fi
	local response
	response=$(_alert_curl_post "$webhook_url" \
		-H "Content-Type: application/json" -d @"$payload_file") || return 1
	# Success: empty body (HTTP 204) or message object with "id":
	case "$response" in
		""|*'"id":'*) return 0 ;;
	esac
	local api_err
	api_err=$(printf '%s' "$response" | sed -n 's/.*"message" *: *"\([^"]*\)".*/\1/p')
	echo "alert_lib: Discord webhook error${api_err:+: $api_err}" >&2
	return 1
}

# _alert_discord_upload file_path payload_file webhook_url — multipart file upload
# Single POST with payload_json + files[0] (unlike Slack's 3-step flow).
_alert_discord_upload() {
	local file_path="$1" payload_file="$2" webhook_url="$3"
	if [ ! -f "$file_path" ]; then
		echo "alert_lib: file not found: $file_path" >&2
		return 1
	fi
	if [ -z "$webhook_url" ] || ! _alert_validate_url "$webhook_url"; then
		echo "alert_lib: invalid or empty Discord webhook URL." >&2
		return 1
	fi
	local response
	response=$(_alert_curl_post "$webhook_url" \
		-F "payload_json=<$payload_file" -F "files[0]=@$file_path") || return 1
	case "$response" in
		""|*'"id":'*) return 0 ;;
	esac
	local api_err
	api_err=$(printf '%s' "$response" | sed -n 's/.*"message" *: *"\([^"]*\)".*/\1/p')
	echo "alert_lib: Discord upload error${api_err:+: $api_err}" >&2
	return 1
}

# _alert_deliver_discord payload_file [attachment_file] — route Discord delivery
# Uses ALERT_DISCORD_WEBHOOK_URL; multipart if attachment exists, else plain JSON POST.
_alert_deliver_discord() {
	local payload_file="$1" attachment="${2:-}"
	if [ -z "${ALERT_DISCORD_WEBHOOK_URL:-}" ]; then
		echo "alert_lib: ALERT_DISCORD_WEBHOOK_URL not set." >&2
		return 1
	fi
	if [ -n "$attachment" ] && [ -f "$attachment" ]; then
		_alert_discord_upload "$attachment" "$payload_file" "$ALERT_DISCORD_WEBHOOK_URL"
	else
		_alert_discord_webhook "$payload_file" "$ALERT_DISCORD_WEBHOOK_URL"
	fi
}

# _alert_handle_discord subject text_file html_file [attachment] — Discord channel handler
# text_file is the payload; subject and html_file are ignored (baked in).
_alert_handle_discord() {
	local text_file="$2" attachment="${4:-}"
	_alert_deliver_discord "$text_file" "$attachment"
}

# _alert_spool_append data_file spool_file — append timestamped entries to digest spool
# Each non-blank line is prefixed with epoch| under exclusive flock (10s timeout).
# No-op if data_file is empty or missing.
_alert_spool_append() {
	local data_file="$1" spool_file="$2"
	if [ ! -f "$data_file" ] || [ ! -s "$data_file" ]; then
		return 0
	fi
	if [ -z "$spool_file" ]; then
		echo "alert_lib: spool_file argument is required." >&2
		return 1
	fi
	local flock_bin
	flock_bin=$(command -v flock 2>/dev/null || true)
	if [ -z "$flock_bin" ]; then
		echo "alert_lib: flock not found, cannot append to spool." >&2
		return 1
	fi
	local now lock_file
	now=$(date +%s)
	lock_file="${spool_file}.lock"
	(
		"$flock_bin" -x -w 10 200 || {
			echo "alert_lib: spool lock timeout, skipping append." >&2
			exit 1
		}
		while IFS= read -r _line; do
			[ -z "$_line" ] && continue
			echo "${now}|${_line}"
		done < "$data_file" >> "$spool_file"
	) 200>"$lock_file"
}

# _alert_digest_check spool_file interval flush_callback — flush spool if age >= interval
# Reads first line's epoch unlocked — worst case is a delayed flush.
_alert_digest_check() {
	local spool_file="$1" interval="$2" flush_callback="$3"
	if [ -z "$spool_file" ]; then
		echo "alert_lib: spool_file argument is required." >&2
		return 1
	fi
	if [ -z "$interval" ]; then
		echo "alert_lib: interval argument is required." >&2
		return 1
	fi
	if [ -z "$flush_callback" ]; then
		echo "alert_lib: flush_callback argument is required." >&2
		return 1
	fi
	if [ ! -f "$spool_file" ] || [ ! -s "$spool_file" ]; then
		return 0
	fi
	local first_epoch
	IFS='|' read -r first_epoch _ < "$spool_file"
	if [ -z "$first_epoch" ]; then
		return 0
	fi
	local now
	now=$(date +%s)
	if [ $((now - first_epoch)) -ge "$interval" ]; then
		_alert_digest_flush "$spool_file" "$flush_callback"
		return $?
	fi
	return 0
}

# _alert_digest_flush spool_file flush_callback — force-flush accumulated entries
# Releases flock before invoking flush_callback (avoids holding lock during delivery).
# Callback receives one argument: the temp file with flushed entries (epoch prefix stripped).
_alert_digest_flush() {
	local spool_file="$1" flush_callback="$2"
	if [ -z "$spool_file" ]; then
		echo "alert_lib: spool_file argument is required." >&2
		return 1
	fi
	if [ -z "$flush_callback" ]; then
		echo "alert_lib: flush_callback argument is required." >&2
		return 1
	fi
	if [ ! -f "$spool_file" ] || [ ! -s "$spool_file" ]; then
		return 0
	fi
	local flock_bin
	flock_bin=$(command -v flock 2>/dev/null || true)
	if [ -z "$flock_bin" ]; then
		echo "alert_lib: flock not found, cannot flush digest." >&2
		return 1
	fi
	local lock_file flush_file
	lock_file="${spool_file}.lock"
	flush_file=$(mktemp "${ALERT_TMPDIR}/alert_digest_flush.XXXXXX")
	(
		"$flock_bin" -x -w 10 200 || {
			echo "alert_lib: digest flush lock timeout." >&2
			exit 1
		}
		# Re-check under lock — another process may have flushed between our size
		# check above and lock acquisition.
		if [ ! -s "$spool_file" ]; then
			exit 0
		fi
		cut -d'|' -f2- "$spool_file" > "$flush_file"
		# Truncate (not unlink) preserves inode for inotifywait/tail -f consumers
		: > "$spool_file"
	) 200>"$lock_file"
	local sub_rc=$?
	if [ "$sub_rc" -ne 0 ]; then
		command rm -f "$flush_file"
		return "$sub_rc"
	fi
	local rc=0
	if [ -s "$flush_file" ]; then
		"$flush_callback" "$flush_file" || rc=$?
	fi
	command rm -f "$flush_file"
	return $rc
}

# alert_dispatch template_dir subject [channels] [attachment_file] — dispatch to enabled channels
# channels: comma-separated list or "all" (default). Per channel, resolves
# $name.text.tpl (fallback $name.message.tpl) + $name.html.tpl from template_dir,
# renders via _alert_tpl_render, then calls handler_fn subject text_file html_file [attachment].
# Continues after individual failures; returns 1 if any channel failed.
alert_dispatch() {
	local template_dir="$1" subject="$2" channels="${3:-all}" attachment="${4:-}"
	local rc=0
	local i name handler enabled
	local text_file html_file

	for i in "${!_ALERT_CHANNEL_NAMES[@]}"; do
		name="${_ALERT_CHANNEL_NAMES[$i]}"
		handler="${_ALERT_CHANNEL_HANDLERS[$i]}"
		enabled="${_ALERT_CHANNEL_ENABLED[$i]}"

		[ "$enabled" = "1" ] || continue

		if [ "$channels" != "all" ]; then
			case ",$channels," in
				*",$name,"*) ;;
				*) continue ;;
			esac
		fi

		text_file=""
		_alert_tpl_resolve "$template_dir" "${name}.text.tpl"
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			text_file=$(mktemp "${ALERT_TMPDIR}/alert_${name}_text.XXXXXX")
			_alert_tpl_render "$_ALERT_TPL_RESOLVED" > "$text_file"
		else
			# Fall back to $name.message.tpl when $name.text.tpl is absent
			_alert_tpl_resolve "$template_dir" "${name}.message.tpl"
			if [ -f "$_ALERT_TPL_RESOLVED" ]; then
				text_file=$(mktemp "${ALERT_TMPDIR}/alert_${name}_text.XXXXXX")
				_alert_tpl_render "$_ALERT_TPL_RESOLVED" > "$text_file"
			fi
		fi

		html_file=""
		_alert_tpl_resolve "$template_dir" "${name}.html.tpl"
		if [ -f "$_ALERT_TPL_RESOLVED" ]; then
			html_file=$(mktemp "${ALERT_TMPDIR}/alert_${name}_html.XXXXXX")
			_alert_tpl_render "$_ALERT_TPL_RESOLVED" > "$html_file"
		fi

		if [ -z "$text_file" ] && [ -z "$html_file" ]; then
			echo "alert_lib: no templates found for channel '$name', skipping." >&2
			continue
		fi

		# Empty placeholders for missing variants so handlers always get valid paths
		if [ -z "$text_file" ]; then
			text_file=$(mktemp "${ALERT_TMPDIR}/alert_${name}_text.XXXXXX")
		fi
		if [ -z "$html_file" ]; then
			html_file=$(mktemp "${ALERT_TMPDIR}/alert_${name}_html.XXXXXX")
		fi

		if ! "$handler" "$subject" "$text_file" "$html_file" "$attachment"; then
			echo "alert_lib: channel '$name' delivery failed." >&2
			rc=1
		fi

		command rm -f "$text_file" "$html_file"
	done

	return $rc
}

# Built-in channels start disabled; consumers enable via alert_channel_enable "<name>".
alert_channel_register "email" "_alert_handle_email"
alert_channel_register "slack" "_alert_handle_slack"
alert_channel_register "telegram" "_alert_handle_telegram"
alert_channel_register "discord" "_alert_handle_discord"
