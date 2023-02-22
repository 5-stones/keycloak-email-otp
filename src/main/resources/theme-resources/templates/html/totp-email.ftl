<#import "template.ftl" as layout>
<@layout.emailLayout>
	<div style="text-align: center;">
		${kcSanitize(msg("emailTOTPBodyHtml",realmName, code, ttl))?no_esc}
	</div>
</@layout.emailLayout>
