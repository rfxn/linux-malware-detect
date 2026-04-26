<!-- Stat blocks -->
<tr>
<td class="content-pad" style="padding:12px 24px;">
<table role="presentation" cellpadding="0" cellspacing="0" border="0" width="100%">
<tr>
<td class="stat-cell" align="center" style="padding:12px 8px;background-color:#fef2f2;border-radius:6px;">
<span style="display:block;font-size:28px;font-weight:bold;color:#dc2626;line-height:1.2;">{{SUMMARY_TOTAL_HITS}}</span>
<span style="display:block;font-size:10px;font-weight:bold;color:#71717a;text-transform:uppercase;letter-spacing:1px;padding-top:2px;">Threats</span>
</td>
<td width="8" style="font-size:0;">&nbsp;</td>
<td class="stat-cell" align="center" style="padding:12px 8px;background-color:#f0fdf4;border-radius:6px;">
<span style="display:block;font-size:28px;font-weight:bold;color:#16a34a;line-height:1.2;">{{SUMMARY_TOTAL_CLEANED}}</span>
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
