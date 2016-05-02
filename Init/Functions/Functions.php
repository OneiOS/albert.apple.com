<?php





function Unbrick_iDevice ( $FairPlayKeyData = "", $AccountTokenCertificate = "", $DeviceCertificate = "", $AccountTokenSignature = "", $AccountToken = "", $iOS_Style = false )
{
	global $DeviceClass;
	if ( $FairPlayKeyData != null )
	{
		$AddFairPlayKeyData = '<key>FairPlayKeyData</key>' . "\n";
		$AddFairPlayKeyData .= '			<data>' . substr ( chunk_split ( $FairPlayKeyData, 68, "\r\n\t\t\t" ), 0, - 5 ) . '</data>';
	}
	else
	{
		$AddFairPlayKeyData = null;
	}
	
	if ( $iOS_Style == false )
	{
		$Parse_Response = '<!DOCTYPE html>' . "\n";
		$Parse_Response .= '<html>' . "\n";
		$Parse_Response .= '<head>' . "\n";
		$Parse_Response .= '<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />' . "\n";
		$Parse_Response .= '<meta name="keywords" content="iTunes Store" />' . "\n";
		$Parse_Response .= '<meta name="description" content="iTunes Store" />' . "\n";
		$Parse_Response .= '<title>' . $DeviceClass . ' Activation</title>' . "\n";
		$Parse_Response .= '<link href="http://static.ips.apple.com/deviceservices/stylesheets/auth_styles.css" charset="utf-8" rel="stylesheet" />' . "\n";
		$Parse_Response .= '<link href="http://static.ips.apple.com/ipa_itunes/stylesheets/shared/common-min.css" charset="utf-8" rel="stylesheet" />' . "\n";
		$Parse_Response .= '<link href="http://static.ips.apple.com/deviceservices/stylesheets/styles.css" charset="utf-8" rel="stylesheet" />' . "\n";
		$Parse_Response .= '<link href="http://static.ips.apple.com/ipa_itunes/stylesheets/pages/IPAJingleEndPointErrorPage-min.css" charset="utf-8" rel="stylesheet" />' . "\n";
		$Parse_Response .= '<script id="protocol" type="text/x-apple-plist">' . "\n";
		$Parse_Response .= '<plist version="1.0">' . "\n";
		$Parse_Response .= '	  <dict>' . "\n";
		$Parse_Response .= '		<key>' . ( $DeviceClass == "iPhone" ? 'iphone' : 'device' ) . '-activation</key>' . "\n";
		$Parse_Response .= '		<dict>' . "\n";
		$Parse_Response .= '		  <key>activation-record</key>' . "\n";
		$Parse_Response .= '		  <dict>' . "\n";
		$Parse_Response .= '		  	' . $AddFairPlayKeyData . "\n";
		$Parse_Response .= '			<key>AccountTokenCertificate</key>' . "\n";
		$Parse_Response .= '			<data>' . substr ( chunk_split ( $AccountTokenCertificate, 68, "\r\n\t\t\t" ), 0, - 5 ) . '</data>' . "\n";
		$Parse_Response .= '			<key>DeviceCertificate</key>' . "\n";
		$Parse_Response .= '			<data>' . substr ( chunk_split ( $DeviceCertificate, 68, "\r\n\t\t\t" ), 0, - 5 ) . '</data>' . "\n";
		$Parse_Response .= '			<key>AccountTokenSignature</key>' . "\n";
		$Parse_Response .= '			<data>' . substr ( chunk_split ( $AccountTokenSignature, 68, "\r\n\t\t\t" ), 0, - 5 ) . '</data>' . "\n";
		$Parse_Response .= '			<key>AccountToken</key>' . "\n";
		$Parse_Response .= '			<data>' . substr ( chunk_split ( $AccountToken, 68, "\r\n\t\t\t" ), 0, - 5 ) . '</data>' . "\n";
		$Parse_Response .= '		  </dict>' . "\n";
		$Parse_Response .= '		  <key>unbrick</key>' . "\n";
		$Parse_Response .= '		  <true/>' . "\n";
		$Parse_Response .= '		</dict>' . "\n";
		$Parse_Response .= '	  </dict>' . "\n";
		$Parse_Response .= '</plist>' . "\n";
		$Parse_Response .= '</script>' . "\n";
		$Parse_Response .= '<script src = "http://static.ips.apple.com/deviceservices/scripts/spinner_reload.js"></script>' . "\n";
		$Parse_Response .= '<script>' . "\n";
		$Parse_Response .= 'var protocolElement = document.getElementById("protocol");' . "\n";
		$Parse_Response .= 'var protocolContent = protocolElement.innerText;iTunes.addProtocol(protocolContent);' . "\n";
		$Parse_Response .= '</script>' . "\n";
		$Parse_Response .= '</head>' . "\n";
		$Parse_Response .= '<body>' . "\n";
		$Parse_Response .= '</body>' . "\n";
		$Parse_Response .= '</html>';
	}
	else
	{
		$Parse_Response = '<?xml version="1.0" encoding="UTF-8" standalone="no"?>' . "\n";
		$Parse_Response .= '<Document disableHistory="true" xmlns="http://www.apple.com/itms/">' . "\n";
		$Parse_Response .= '  <Protocol>' . "\n";
		$Parse_Response .= '   <plist version="1.0" >' . "\n";
		$Parse_Response .= '      <dict>' . "\n";
		$Parse_Response .= '        <key>' . ( $DeviceClass == "iPhone" ? 'iphone' : 'device' ) . '-activation</key>' . "\n";
		$Parse_Response .= '        <dict>' . "\n";
		$Parse_Response .= '          <key>activation-record</key>' . "\n";
		$Parse_Response .= '          <dict>' . "\n";
		$Parse_Response .= '		  	' . $AddFairPlayKeyData . "\n";
		$Parse_Response .= '            <key>AccountTokenCertificate</key>' . "\n";
		$Parse_Response .= '			<data>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURaekNDQWsrZ0F3SUJBZ0lCQWpBTkJna3Foa2lHOXcwQkFRVUZBREI1TVFzd0NRWURWUVFHRXdKVlV6RVQKTUJFR0ExVUVDaE1LUVhCd2JHVWdTVzVqTGpFbU1DUUdBMVVFQ3hNZFFYQndiR1VnUTJWeWRHbG1hV05oZEdsdgpiaUJCZFhSb2IzSnBkSGt4TFRBckJnTlZCQU1USkVGd2NHeGxJR2xRYUc5dVpTQkRaWEowYVdacFkyRjBhVzl1CklFRjFkR2h2Y21sMGVUQWVGdzB3TnpBME1UWXlNalUxTURKYUZ3MHhOREEwTVRZeU1qVTFNREphTUZzeEN6QUoKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFLRXdwQmNIQnNaU0JKYm1NdU1SVXdFd1lEVlFRTEV3eEJjSEJzWlNCcApVR2h2Ym1VeElEQWVCZ05WQkFNVEYwRndjR3hsSUdsUWFHOXVaU0JCWTNScGRtRjBhVzl1TUlHZk1BMEdDU3FHClNJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRREZBWHpSSW1Bcm1vaUhmYlMyb1BjcUFmYkV2MGQxams3R2JuWDcKKzRZVWx5SWZwcnpCVmRsbXoySkhZdjErMDRJekp0TDdjTDk3VUk3ZmswaTBPTVkwYWw4YStKUFFhNFVnNjExVApicUV0K25qQW1Ba2dlM0hYV0RCZEFYRDlNaGtDN1QvOW83N3pPUTFvbGk0Y1VkemxuWVdmem1XMFBkdU94dXZlCkFlWVk0d0lEQVFBQm80R2JNSUdZTUE0R0ExVWREd0VCL3dRRUF3SUhnREFNQmdOVkhSTUJBZjhFQWpBQU1CMEcKQTFVZERnUVdCQlNob05MK3Q3UnovcHNVYXEvTlBYTlBIKy9XbERBZkJnTlZIU01FR0RBV2dCVG5OQ291SXQ0NQpZR3UwbE01M2cyRXZNYUI4TlRBNEJnTlZIUjhFTVRBdk1DMmdLNkFwaGlkb2RIUndPaTh2ZDNkM0xtRndjR3hsCkxtTnZiUzloY0hCc1pXTmhMMmx3YUc5dVpTNWpjbXd3RFFZSktvWklodmNOQVFFRkJRQURnZ0VCQUY5cW1yVU4KZEErRlJPWUdQN3BXY1lUQUsrcEx5T2Y5ek9hRTdhZVZJODg1VjhZL0JLSGhsd0FvK3pFa2lPVTNGYkVQQ1M5Vgp0UzE4WkJjd0QvK2Q1WlFUTUZrbmhjVUp3ZFBxcWpubTlMcVRmSC94NHB3OE9OSFJEenhIZHA5NmdPVjNBNCs4CmFia29BU2ZjWXF2SVJ5cFhuYnVyM2JSUmhUekFzNFZJTFM2alR5Rll5bVplU2V3dEJ1Ym1taWdvMWtDUWlaR2MKNzZjNWZlREF5SGIyYnpFcXR2eDNXcHJsanRTNDZRVDVDUjZZZWxpblpuaW8zMmpBelJZVHh0UzZyM0pzdlpEaQpKMDcrRUhjbWZHZHB4d2dPKzdidFcxcEZhcjBaakY5L2pZS0tuT1lOeXZDcndzemhhZmJTWXd6QUc1RUpvWEZCCjRkK3BpV0hVRGNQeHRjYz0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=</data>' . "\n";
		$Parse_Response .= '            <key>DeviceCertificate</key>' . "\n";
		$Parse_Response .= '            <data>LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUM4akNDQWx1Z0F3SUJBZ0lKVHlXakIyNmZVWnVDTUEwR0NTcUdTSWIzRFFFQkJRVUFNRm94Q3pBSkJnTlYKQkFZVEFsVlRNUk13RVFZRFZRUUtFd3BCY0hCc1pTQkpibU11TVJVd0V3WURWUVFMRXd4QmNIQnNaU0JwVUdodgpibVV4SHpBZEJnTlZCQU1URmtGd2NHeGxJR2xRYUc5dVpTQkVaWFpwWTJVZ1EwRXdIaGNOTVRRd016SXhNREEwCk1URXdXaGNOTVRjd016SXhNREEwTVRFd1dqQ0JnekV0TUNzR0ExVUVBeFlrT0RrMU56QTVOemN0TnpWQlF5MDAKTjBKR0xUazVNRFl0T0RJMk16Y3dNakpDTjBJME1Rc3dDUVlEVlFRR0V3SlZVekVMTUFrR0ExVUVDQk1DUTBFeApFakFRQmdOVkJBY1RDVU4xY0dWeWRHbHViekVUTUJFR0ExVUVDaE1LUVhCd2JHVWdTVzVqTGpFUE1BMEdBMVVFCkN4TUdhVkJvYjI1bE1JR2ZNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0R05BRENCaVFLQmdRRHpPVFkrcEppWVVpNXUKVzZ6dXNKaWZyMWdFQjhjWUtBMHpzL2tKOERtRk1RSHRuSEFHMnJtN1orWFk4cVBoOG9CRjFWSTRjY1Uwdmc2SQpDMENyU3hXN3V3Y05Gc0MvNHowWjhhTlNvZmorbDVmWDJSVVA3QkkzREFIaWwyei9heFhaZ0dveGNpZzlhMHJ4CmNzT2JqclZuMVBjK1pJcllHSjJvYk1ZczZvQWhZd0lEQVFBQm80R1ZNSUdTTUI4R0ExVWRJd1FZTUJhQUZMTCsKSVNORWhwVnFlZFdCSm81ekVOaW5USTUwTUIwR0ExVWREZ1FXQkJSUEFsWUdWemthZTk0djZ3UUFEaHpGNEo3ZwpyakFNQmdOVkhSTUJBZjhFQWpBQU1BNEdBMVVkRHdFQi93UUVBd0lGb0RBZ0JnTlZIU1VCQWY4RUZqQVVCZ2dyCkJnRUZCUWNEQVFZSUt3WUJCUVVIQXdJd0VBWUtLb1pJaHZkalpBWUtBZ1FDQlFBd0RRWUpLb1pJaHZjTkFRRUYKQlFBRGdZRUFOeUxvVTFjakx1bGxESi8vQk5wNGtrWHllUHpMRnhBNXFyQ0YzWVA2dmkxTmlZK2dqOEdCM0drTAoya01yMFdCblRvSDExclAvUkluNXNoYVM2K05TQjl2WTAzQmRJNzRHcm9IMkRiK0haL3F1Q0lpZ3BCNzJ0b01jClg0ZzNoWDlwd29Fb0ErU2lGdmdnNTJNTndKa29SVXBNMHhFaElGeUZuMFdxYTVxWnpmQT0KLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo=</data>' . "\n";
		$Parse_Response .= '            <key>AccountTokenSignature</key>' . "\n";
		$Parse_Response .= '            <data>' . $AccountTokenSignature . '</data>' . "\n";
		$Parse_Response .= '            <key>AccountToken</key>' . "\n";
		$Parse_Response .= '            <data>' . $AccountToken . '</data>' . "\n";
		$Parse_Response .= '          </dict>' . "\n";
		$Parse_Response .= '          <key>unbrick</key>' . "\n";
		$Parse_Response .= '          <true/>' . "\n";
		$Parse_Response .= '        </dict>' . "\n";
		$Parse_Response .= '      </dict>' . "\n";
		$Parse_Response .= '    </plist>' . "\n";
		$Parse_Response .= '  </Protocol>' . "\n";
		$Parse_Response .= '  <ScrollView rightInset="0" topInset="0" bottomInset="0" leftInset="0" stretchiness="1" horzScroll="as needed" vertScroll="as needed">' . "\n";
		$Parse_Response .= '    <View>' . "\n";
		$Parse_Response .= '      <Include target="main" url="https://albert.apple.com/albert/static/fontstyles.css"/>' . "\n";
		$Parse_Response .= '      <MatrixView viewName="iphoneSystemsWizard" rightInset="0" bottomInset="0" leftInset="0" topInset="0" rowFormat="100%,*">' . "\n";
		$Parse_Response .= '        <VBoxView>' . "\n";
		$Parse_Response .= '          <HBoxView minWidth="774" leftInset="50" rightInset="50">' . "\n";
		$Parse_Response .= '            <View stretchiness="1"/>' . "\n";
		$Parse_Response .= '            <VBoxView minWidth="774" topInset="0" leftInset="0" rightInset="0">' . "\n";
		$Parse_Response .= '              <PictureView width="11" topInset="8" height="12" rightInset="2" url="https://albert.apple.com/images/lock.png"/>' . "\n";
		$Parse_Response .= '              <HBoxView leftInset="0" rightInset="0" topInset="3">' . "\n";
		$Parse_Response .= '                <PictureView width="42" topInset="0" height="66" url="https://albert.apple.com/albert/images/apple_chrome.png"/>' . "\n";
		$Parse_Response .= '                <View stretchiness="1"/>' . "\n";
		$Parse_Response .= '                <PictureView width="120" topInset="8" height="37" rightInset="2" url="https://albert.apple.com/albert/images/iphonereg/logo.jpg"/>' . "\n";
		$Parse_Response .= '              </HBoxView>' . "\n";
		$Parse_Response .= '            </VBoxView>' . "\n";
		$Parse_Response .= '            <View stretchiness="1"/>' . "\n";
		$Parse_Response .= '          </HBoxView>' . "\n";
		$Parse_Response .= '          <HBoxView minWidth="770" leftInset="50" rightInset="50">' . "\n";
		$Parse_Response .= '            <View stretchiness="1"/>' . "\n";
		$Parse_Response .= '            <VBoxView topInset="0" leftInset="0" rightInset="0">' . "\n";
		$Parse_Response .= '              <View topInset="15">' . "\n";
		$Parse_Response .= '                <View rightInset="0" borderColor="999999" topInset="0" bottomInset="0" leftInset="0" borderWidth="1">' . "\n";
		$Parse_Response .= '                  <VBoxView minWidth="600" topInset="48" leftInset="85" bottomInset="50" rightInset="85">' . "\n";
		$Parse_Response .= '                    <TextView topInset="0" normalStyle="lucida18" leftInset="0" rightInset="0" bottomInset="0" textJust="center"/>' . "\n";
		$Parse_Response .= '                    <View height="30"/>' . "\n";
		$Parse_Response .= '                    <TextView topInset="0" styleSet="normal13" leftInset="0" rightInset="0" bottomInset="0" textJust="center"/>' . "\n";
		$Parse_Response .= '                    <TextView/>' . "\n";
		$Parse_Response .= '                    <TextView/>' . "\n";
		$Parse_Response .= '                    <View stretchiness="1"/>' . "\n";
		$Parse_Response .= '                  </VBoxView>' . "\n";
		$Parse_Response .= '                </View>' . "\n";
		$Parse_Response .= '                <PictureView leftInset="0" width="8" topInset="0" height="8" url="https://albert.apple.com/images/boxline/boxline_ffffff_topl.png"/>' . "\n";
		$Parse_Response .= '                <PictureView width="8" topInset="0" height="8" rightInset="0" url="https://albert.apple.com/images/boxline/boxline_ffffff_topr.png"/>' . "\n";
		$Parse_Response .= '               <PictureView leftInset="0" width="8" height="8" bottomInset="0" url="https://albert.apple.com/images/boxline/boxline_ffffff_botl.png"/>' . "\n";
		$Parse_Response .= '                <PictureView width="8" height="8" rightInset="0" bottomInset="0" url="https://albert.apple.com/images/boxline/boxline_ffffff_botr.png"/>' . "\n";
		$Parse_Response .= '              </View>' . "\n";
		$Parse_Response .= '            </VBoxView>' . "\n";
		$Parse_Response .= '            <View stretchiness="1"/>' . "\n";
		$Parse_Response .= '          </HBoxView>' . "\n";
		$Parse_Response .= '        </VBoxView>' . "\n";
		$Parse_Response .= '        <VBoxView leftInset="0" rightInset="0">' . "\n";
		$Parse_Response .= '          <View height="88"/>' . "\n";
		$Parse_Response .= '          <TextView topInset="2" leftInset="0" styleSet="basic9" textJust="center"/>' . "\n";
		$Parse_Response .= '          <TextView topInset="2" leftInset="0" styleSet="basic9" textJust="center"/>' . "\n";
		$Parse_Response .= '          <TextView topInset="2" leftInset="0" styleSet="basic9" textJust="center"/>' . "\n";
		$Parse_Response .= '          <TextView topInset="2" leftInset="0" styleSet="basic9" textJust="center"/>' . "\n";
		$Parse_Response .= '          <TextView topInset="2" leftInset="0" styleSet="basic9" textJust="center"/>' . "\n";
		$Parse_Response .= '          <View height="8"/>' . "\n";
		$Parse_Response .= '          <View height="30"/>' . "\n";
		$Parse_Response .= '          <HBoxView bottomInset="0">' . "\n";
		$Parse_Response .= '            <View stretchiness="1"/>' . "\n";
		$Parse_Response .= '            <TextView topInset="2" leftInset="0" styleSet="basic9" textJust="center">Copyright</TextView>' . "\n";
		$Parse_Response .= '            <View width="2"/>' . "\n";
		$Parse_Response .= '            <TextView topInset="2" leftInset="0" styleSet="basic9" textJust="center"/>' . "\n";
		$Parse_Response .= '            <View width="2"/>' . "\n";
		$Parse_Response .= '            <TextView topInset="2" leftInset="0" styleSet="basic9" textJust="center">' . "\n";
		$Parse_Response .= '              2016 Apple Inc. - LunaWolf Corp.' . "\n";
		$Parse_Response .= '              <OpenURL target="main" url="http://www.apple.com/legal/">Todos los derechos reservados.</OpenURL>' . "\n";
		$Parse_Response .= '              |' . "\n";
		$Parse_Response .= '              <OpenURL target="main" url="http://www.apple.com/legal/iphone/us/privacy">Privacy Policies</OpenURL>' . "\n";
		$Parse_Response .= '              |' . "\n";
		$Parse_Response .= '              <OpenURL target="main" url="http://www.apple.com/legal/iphone/us/terms">Terms &amp; Conditions</OpenURL>' . "\n";
		$Parse_Response .= '            </TextView>' . "\n";
		$Parse_Response .= '            <View stretchiness="1"/>' . "\n";
		$Parse_Response .= '          </HBoxView>' . "\n";
		$Parse_Response .= '        </VBoxView>' . "\n";
		$Parse_Response .= '      </MatrixView>' . "\n";
		$Parse_Response .= '    </View>' . "\n";
		$Parse_Response .= '  </ScrollView>' . "\n";
		$Parse_Response .= '</Document>' . "\n";
	}
	
	return $Parse_Response;
}

function Setting_iTunes ( )
{
	$Parse_Response = '';
	include ( "TEMPLATES/Setting_iTunes_Meta.tpl" );
	include ( "TEMPLATES/Setting_iTunes_Plist.Plist" );
	include ( "TEMPLATES/Setting_iTunes_Footer.tpl" );
	
	return $Parse_Response;
}

function Merruks_Error ( $SerialNumber )
{
	$Parse_Response = '';
	include ( "TEMPLATES/Merruks_Error_Meta.tpl" );
	include ( "TEMPLATES/Merruks_Error_Header.tpl" );
	include ( "TEMPLATES/Merruks_Error_Content.tpl" );
	include ( "TEMPLATES/Merruks_Error_Footer.tpl" );
	
	return $Parse_Response;
}

function Get_Var_Exists ( $Var )
{
	$Var_Exists = get_defined_vars ( );
	
	if ( array_key_exists ( $Var, $Var_Exists ) === true )
	{
		$Variable_Status = true;
	}
	else
	{
		$Variable_Status = false;
	}
	
	return $Variable_Status;
}


function Check_iDevice ( $ProductType, $Data = false, $DisplayName = false )
{
	// Iphone's
	if ( $ProductType == "iPhone1,1" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 2G (EDGE)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 2G (EDGE)"
	if ( $ProductType == "iPhone1,2" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 3G";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 3G"
	if ( $ProductType == "iPhone2,1" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 3GS";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 3GS"
	if ( $ProductType == "iPhone3,1" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 4 (GSM)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 4 (GSM)"
	if ( $ProductType == "iPhone3,2" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 4 (GSM) R2";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 4 (GSM) R2"
	if ( $ProductType == "iPhone3,3" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 4 (CDMA)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 4 (CDMA)"
	if ( $ProductType == "iPhone4,1" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 4S";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 4S"
	if ( $ProductType == "iPhone5,1" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 5 (GSM)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 5 (GSM)"
	if ( $ProductType == "iPhone5,2" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 5 (Global)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 5 (Global)"
	if ( $ProductType == "iPhone5,3" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 5c (GSM+CDMA)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 5c (GSM+CDMA)"
	if ( $ProductType == "iPhone5,4" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 5c (Global)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 5c (Global)"
	if ( $ProductType == "iPhone6,1" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 5s (GSM+CDMA)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 5s (GSM+CDMA)"
	if ( $ProductType == "iPhone6,2" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPhone 5s (Global)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPhone 5s (Global)"
	  
	// iPod's
	if ( $ProductType == "iPod1,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPod Touch (1 Gen)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPod Touch (1 Gen)"
	if ( $ProductType == "iPod2,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPod Touch (2 Gen)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPod Touch (2 Gen)"
	if ( $ProductType == "iPod3,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPod Touch (3 Gen)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPod Touch (3 Gen)"
	if ( $ProductType == "iPod4,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPod Touch (4 Gen)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPod Touch (4 Gen)"
	if ( $ProductType == "iPod5,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPod Touch (5 Gen)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPod Touch (5 Gen)"
	  
	// iPad's
	if ( $ProductType == "iPad1,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad (1 Gen)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad"
	if ( $ProductType == "iPad1,2" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 3G (1 Gen)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 3G"
	if ( $ProductType == "iPad2,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 2 (WiFi)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 2 (WiFi)"
	if ( $ProductType == "iPad2,2" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 2 (GSM)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 2 (GSM)"
	if ( $ProductType == "iPad2,3" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 2 (CDMA)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 2 (CDMA)"
	if ( $ProductType == "iPad2,4" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 2 (WiFi) R2";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 2 (WiFi) R2"
	if ( $ProductType == "iPad2,5" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad Mini (WiFi)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad Mini (WiFi)"
	if ( $ProductType == "iPad2,6" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad Mini (GSM)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad Mini (GSM)"
	if ( $ProductType == "iPad2,7" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad Mini (Global)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad Mini (Global)"
	if ( $ProductType == "iPad3,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 3 (WiFi)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 3 (WiFi)"
	if ( $ProductType == "iPad3,2" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 3 (CDMA)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 3 (CDMA)"
	if ( $ProductType == "iPad3,3" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 3 (GSM)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 3 (GSM)"
	if ( $ProductType == "iPad3,4" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 4 (WiFi)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 4 (WiFi)"
	if ( $ProductType == "iPad3,5" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 4 (GSM)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 4 (GSM)"
	if ( $ProductType == "iPad3,6" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad 4 (Global)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad 4 (Global)"
	if ( $ProductType == "iPad4,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad Air (WiFi)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad Air (WiFi)"
	if ( $ProductType == "iPad4,2" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad Air (Cellular)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad Air (Cellular)"
	if ( $ProductType == "iPad4,4" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad Mini 2G Retina (WiFi)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad Mini 2G Retina (WiFi)"
	if ( $ProductType == "iPad4,5" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "iPad Mini 2G Retina (Cellular)";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "iPad Mini 2G Retina (Cellular)"
	  
	// Apple TV's
	if ( $ProductType == "AppleTV2,1" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "Apple TV 2G";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "Apple TV 2G"
	if ( $ProductType == "AppleTV3,1" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "Apple TV 3G";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "Apple TV 3G"
	if ( $ProductType == "AppleTV3,2" )
	{
		$LookForSIMStatus = true;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "Apple TV 3G Rev. A";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "Apple TV 3G Rev. A"
	  
	// Personal Computers
	if ( $ProductType == "x86_64" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "Simulator 1 WTF";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "Simulator"
	if ( $ProductType == "i386" )
	{
		$LookForSIMStatus = false;
		if ( $Data == false )
		{
			return $LookForSIMStatus;
		}
		else
		{
			if ( $DisplayName == true )
			{
				return "Simulator 2 WTF";
			}
			else
			{
				return $ProductType;
			}
		}
	} // "Simulator"
	
	return $LookForSIMStatus;
}

function Check_SIMStatus ( $SIMStatus ) {

	$SStatus = false;

	if ( ( $SIMStatus == "kCTSIMSupportSIMStatusNotReady" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusPINLocked" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusPUKLocked" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusNotInserted" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusBlacklisted" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusMemoryFailure" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusFixedDialingLocked" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusOperatorSubsetLocked" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusServiceProviderLocked" )
					or ( $SIMStatus == "kCTSIMSupportSIMPINEntryAttemptsRemainingCount" )
					or ( $SIMStatus == "kCTSIMSupportSIMPUKEntryAttemptsRemainingCount" )
					or ( $SIMStatus == "kCTSIMSupportSIMTrayStatusUnknown" ) ) {
		$SStatus = false;

	} elseif ( ( $SIMStatus == "kCTSIMSupportSIMStatusReady" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusNetworkLocked" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusOperatorLocked" )
					or ( $SIMStatus == "kCTSIMSupportSIMStatusCorporateLocked" ) ) {
		$SStatus = true;

	}

	return $SStatus;
}



	?>