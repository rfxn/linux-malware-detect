<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Malware Detect Alert for {{PANEL_USER}}@{{HOSTNAME}}</title>
<style type="text/css">
@media only screen and (max-width: 480px) {
  .email-container { padding: 8px !important; }
  .email-body { border-radius: 0 !important; border-left: 0 !important; border-right: 0 !important; }
  .content-pad { padding-left: 16px !important; padding-right: 16px !important; }
  .stat-cell { padding: 8px 4px !important; }
}
</style>
</head>
<body style="margin:0;padding:0;background-color:#f4f4f5;font-family:Arial,Helvetica,sans-serif;font-size:14px;color:#09090b;-webkit-text-size-adjust:100%;-ms-text-size-adjust:100%;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="background-color:#f4f4f5;">
<tr>
<td class="email-container" align="center" style="padding:20px 10px;">
<!--[if mso]>
<table role="presentation" align="center" width="700" cellpadding="0" cellspacing="0" border="0"><tr><td>
<![endif]-->
<table class="email-body" role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="max-width:700px;background-color:#ffffff;border:1px solid #d4d4d8;border-radius:8px;overflow:hidden;">
<!-- Teal brand bar -->
<tr>
<td style="background-color:#0891b2;padding:20px 24px 18px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td>
<span style="font-family:'Courier New',Courier,monospace;font-size:20px;font-weight:bold;color:#ffffff;letter-spacing:-0.5px;">rfxn</span>
<span style="color:rgba(255,255,255,0.4);padding:0 8px;font-size:18px;">|</span>
<span style="font-family:'Courier New',Courier,monospace;font-size:10px;font-weight:bold;color:rgba(255,255,255,0.7);text-transform:uppercase;letter-spacing:2px;">malware detect</span>
</td>
<td align="right" style="font-family:'Courier New',Courier,monospace;font-size:12px;"><a style="color:#ffffff;text-decoration:none;">{{HOSTNAME}}</a></td>
</tr>
</table>
</td>
</tr>
<!-- Accent sub-line -->
<tr>
<td style="background-color:#0e7490;height:2px;font-size:0;line-height:0;">&nbsp;</td>
</tr>
<!-- Meta bar: account + threat badge -->
<tr>
<td style="background-color:#f4f4f5;padding:8px 24px;border-bottom:1px solid #d4d4d8;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td style="color:#52525b;font-size:11px;font-weight:bold;text-transform:uppercase;letter-spacing:1px;">Account: {{PANEL_USER}}</td>
<td align="right" style="white-space:nowrap;font-size:11px;">
<span style="display:inline-block;background-color:#dc2626;color:#ffffff;padding:2px 10px;border-radius:10px;font-weight:bold;font-family:'Courier New',Courier,monospace;">{{USER_TOTAL_HITS}} threat(s)</span>
</td>
</tr>
</table>
</td>
</tr>
<!-- Metadata grid -->
<tr>
<td class="content-pad" style="padding:12px 24px 4px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="font-size:13px;">
<tr>
<td style="padding:3px 0;color:#71717a;width:80px;">Scan ID</td>
<td style="padding:3px 0;color:#09090b;font-family:'Courier New',Courier,monospace;font-size:12px;">{{SCAN_ID}}</td>
</tr>
<tr>
<td style="padding:3px 0;color:#71717a;">Path</td>
<td style="padding:3px 0;color:#09090b;font-size:12px;word-break:break-all;">{{SCAN_PATH}}</td>
</tr>
</table>
</td>
</tr>
<!-- Stat blocks (per-user: threats + cleaned + quarantined) -->
<tr>
<td class="content-pad" style="padding:12px 24px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td class="stat-cell" align="center" style="padding:12px 8px;background-color:#fef2f2;border-radius:6px;">
<span style="display:block;font-size:28px;font-weight:bold;color:#dc2626;line-height:1.2;">{{USER_TOTAL_HITS}}</span>
<span style="display:block;font-size:10px;font-weight:bold;color:#71717a;text-transform:uppercase;letter-spacing:1px;padding-top:2px;">Threats</span>
</td>
<td width="8" style="font-size:0;">&nbsp;</td>
<td class="stat-cell" align="center" style="padding:12px 8px;background-color:#f0fdf4;border-radius:6px;">
<span style="display:block;font-size:28px;font-weight:bold;color:#16a34a;line-height:1.2;">{{USER_TOTAL_CLEANED}}</span>
<span style="display:block;font-size:10px;font-weight:bold;color:#71717a;text-transform:uppercase;letter-spacing:1px;padding-top:2px;">Cleaned</span>
</td>
<td width="8" style="font-size:0;">&nbsp;</td>
<td class="stat-cell" align="center" style="padding:12px 8px;background-color:#eff6ff;border-radius:6px;">
<span style="display:block;font-size:28px;font-weight:bold;color:#2563eb;line-height:1.2;">{{SUMMARY_TOTAL_QUARANTINED}}</span>
<span style="display:block;font-size:10px;font-weight:bold;color:#71717a;text-transform:uppercase;letter-spacing:1px;padding-top:2px;">Quarantined</span>
</td>
</tr>
</table>
</td>
</tr>
<!-- By type + quarantine status -->
<tr>
<td class="content-pad" style="padding:0 24px 12px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="font-size:12px;color:#52525b;">
<tr>
<td style="padding:2px 0;">{{SUMMARY_BY_TYPE_HTML}} &nbsp;&middot;&nbsp; {{SUMMARY_QUARANTINE_STATUS}}</td>
</tr>
</table>
</td>
</tr>
<!-- Conditional sections -->
<tr>
<td class="content-pad" style="padding:0 24px 8px;">
{{QUARANTINE_WARNING_HTML}}
{{CLEANED_SECTION_HTML}}
{{SUSPENDED_SECTION_HTML}}
</td>
</tr>
<!-- Threat Details heading -->
<tr>
<td class="content-pad" style="padding:0 24px 12px;">
<span style="font-size:11px;font-weight:bold;color:#52525b;text-transform:uppercase;letter-spacing:1px;">Threat Details</span>
</td>
</tr>
<!-- Content area (closed by footer) -->
<tr>
<td class="content-pad" style="padding:0 24px;">
