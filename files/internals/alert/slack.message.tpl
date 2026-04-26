{
	"blocks": [
		{
			"type": "header",
			"text": {
				"type": "plain_text",
				"text": "LMD Alert: {{HOSTNAME}}"
			}
		},
		{
			"type": "section",
			"text": {
				"type": "mrkdwn",
				"text": "*{{TOTAL_HITS}}* threat(s) detected  |  {{SUMMARY_TOTAL_QUARANTINED}} quarantined  |  {{SUMMARY_TOTAL_CLEANED}} cleaned\n{{SUMMARY_BY_TYPE}}  |  {{SUMMARY_QUARANTINE_STATUS}}  |  {{SCAN_STARTED}}"
			}
		},
{{ENTRY_BLOCKS}}
		{
			"type": "divider"
		},
		{
			"type": "context",
			"elements": [
				{
					"type": "mrkdwn",
					"text": "LMD {{LMD_VERSION}} | <https://www.rfxn.com/projects/linux-malware-detect|rfxn.com>"
				}
			]
		}
	]
}
