<!-- Entry card -->
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="margin-bottom:16px;border:1px solid #d4d4d8;border-radius:8px;overflow:hidden;">
<!-- Hit type top line -->
<tr>
<td style="background-color:{{HIT_TYPE_COLOR}};height:3px;font-size:0;line-height:0;">&nbsp;</td>
</tr>
<!-- Signature row: full-width name with counter right-aligned -->
<tr>
<td style="background-color:#f4f4f5;padding:10px 16px;border-bottom:1px solid #d4d4d8;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td style="font-family:'Courier New',Courier,monospace;font-size:13px;font-weight:bold;color:#09090b;word-break:break-all;">{{HIT_SIGNATURE_HTML}}</td>
<td align="right" style="white-space:nowrap;padding-left:12px;vertical-align:top;">
<span style="color:#71717a;font-size:11px;font-family:'Courier New',Courier,monospace;">{{ENTRY_NUM}}/{{ENTRY_TOTAL}}</span>
</td>
</tr>
</table>
</td>
</tr>
<!-- Detail rows -->
<tr>
<td style="padding:0;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%" style="font-size:13px;">
<!-- Hit type -->
<tr>
<td style="padding:10px 16px 4px;color:#71717a;width:80px;vertical-align:top;">Type</td>
<td style="padding:10px 16px 4px;">
<span style="display:inline-block;background-color:{{HIT_TYPE_COLOR}};color:#ffffff;padding:2px 10px;border-radius:10px;font-size:11px;font-weight:bold;font-family:'Courier New',Courier,monospace;">{{HIT_TYPE_LABEL}}</span>
</td>
</tr>
<!-- File path -->
<tr>
<td style="padding:4px 16px;color:#71717a;vertical-align:top;">File</td>
<td style="padding:4px 16px;color:#09090b;font-family:'Courier New',Courier,monospace;font-size:12px;word-break:break-all;">{{HIT_FILE_HTML}}</td>
</tr>
<!-- Quarantine status -->
<tr>
<td style="padding:4px 16px 10px;color:#71717a;vertical-align:top;">Status</td>
<td style="padding:4px 16px 10px;font-size:13px;">{{QUARANTINE_STATUS_HTML}}</td>
</tr>
</table>
</td>
</tr>
</table>
