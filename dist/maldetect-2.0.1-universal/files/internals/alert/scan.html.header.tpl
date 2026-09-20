<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Malware Detect Alert for {{HOSTNAME}}</title>
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
<!-- Meta bar: scan overview + status badge -->
<tr>
<td style="background-color:#f4f4f5;padding:8px 24px;border-bottom:1px solid #d4d4d8;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td style="color:#52525b;font-size:11px;font-weight:bold;text-transform:uppercase;letter-spacing:1px;">Scan Overview</td>
<td align="right" style="white-space:nowrap;font-size:11px;">
{{THREAT_BADGE_HTML}}
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
<td style="padding:3px 0;color:#71717a;">Started</td>
<td style="padding:3px 0;color:#09090b;font-size:12px;">{{SCAN_STARTED}}</td>
</tr>
<tr>
<td style="padding:3px 0;color:#71717a;">Path</td>
<td style="padding:3px 0;color:#09090b;font-size:12px;word-break:break-all;">{{SCAN_PATH}}</td>
</tr>
<tr>
<td style="padding:3px 0;color:#71717a;">Range</td>
<td style="padding:3px 0;color:#09090b;">{{SCAN_RANGE}} day(s) &nbsp;&middot;&nbsp; {{SCAN_ELAPSED}}s elapsed [find: {{FILELIST_ELAPSED}}s] &nbsp;&middot;&nbsp; {{TOTAL_FILES}} files</td>
</tr>
</table>
</td>
</tr>
<!-- Scan result section (stat blocks or clean celebration) -->
{{SCAN_RESULT_HTML}}
<!-- Content area (closed by footer) -->
<tr>
<td class="content-pad" style="padding:0 24px;">
