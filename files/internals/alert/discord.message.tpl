{
	"embeds": [
		{
			"title": "LMD Alert: {{HOSTNAME}}",
			"description": "**{{TOTAL_HITS}}** threat(s) detected | {{SUMMARY_TOTAL_QUARANTINED}} quarantined | {{SUMMARY_TOTAL_CLEANED}} cleaned\n{{SUMMARY_BY_TYPE}} | {{SCAN_STARTED}}",
			"color": 557490,
			"fields": [
{{ENTRY_FIELDS}}
				{
					"name": "\u200b",
					"value": "{{SUMMARY_QUARANTINE_STATUS}}",
					"inline": false
				}
			],
			"footer": {
				"text": "LMD {{LMD_VERSION}} | rfxn.com"
			}
		}
	]
}
