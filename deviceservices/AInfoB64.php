<?php


	//
	//
	if ( isset ( $_POST [ 'activation-info-base64' ] ) ) {

		$DeviceARecv = base64_decode( $_POST['activation-info-base64'] );
	}


	//
	//
	if( !$DeviceARecv ) {

		header ( CONTENT_TEXT );
		header ( "HTTP/1.1 404 Not Found" );
		echo "File Not Found";
		die ( );
	}


	//
	//
	$Msg->Info( "iTunes Post = Hack", "AInfo B64" );


	//
	//
	$DeviceEncoded = new DOMDocument;
	$DeviceEncoded->loadXML( $DeviceARecv );

	//
	$DeviceDActivation = base64_decode( $DeviceEncoded->getElementsByTagName('data')->item(0)->nodeValue );

	//
	$DeviceDecoded = new DOMDocument;
	$DeviceDecoded->loadXML( $DeviceDActivation );

	//
	$Nodes = $DeviceDecoded->getElementsByTagName('dict')->item(0)->getElementsByTagName('*');


	//
	//
	for ($i = 0; $i < $Nodes->length - 1; $i=$i+2) {
	
	
		//
		//
		switch ( $Nodes->item($i)->nodeValue ) {

			case "ActivationRandomness":
				$ActivationRandomness = $Nodes->item($i + 1)->nodeValue;
				break;

			case "DeviceCertRequest":
				$DeviceCert = $Nodes->item($i + 1)->nodeValue;
				break;
	
			case "DeviceClass":
				$DeviceClass = $Nodes->item($i + 1)->nodeValue;
				break;
	
			case "SerialNumber":
				$SerialNumber = $Nodes->item($i + 1)->nodeValue;
				break;
	
			case "UniqueDeviceID":
				$UDID = $Nodes->item($i + 1)->nodeValue;
				break;

			case "InternationalMobileEquipmentIdentity":
				$IMEI = $Nodes->item($i + 1)->nodeValue;
				break;

			case "InternationalMobileSubscriberIdentity":
				$IMSI = $Nodes->item($i + 1)->nodeValue;
				break;

			case "IntegratedCircuitCardIdentity":
				$ICCID = $Nodes->item($i + 1)->nodeValue;
				break;

			case "UniqueChipID":
				$UCID = $Nodes->item($i + 1)->nodeValue;
				break;

			case "ProductType":
				$ProductType = $Nodes->item($i + 1)->nodeValue;
				break;

			case "ActivationState":
				$ActivationState = $Nodes->item($i + 1)->nodeValue;
				break;

			case "ProductVersion":
				$ProductVersion = $Nodes->item($i + 1)->nodeValue;
				break;

			case "BuildVersion":
				$BuildVersion = $Nodes->item($i + 1)->nodeValue;
				break;
		}
	}


	// Prepare to Path
	//
	$DevicePath = DEVICE_ACTIVATION . $SerialNumber . "_" . $ProductType . "_" . $BuildVersion;


	// Check Path
	//
	$isDevicePath = Create_Dir ( $DevicePath, $Mode = 0755 );


	// Prepare iTunes Request POST Data.
	//
	file_put_contents ( $DevicePath . DS . "TicketRequest.json", json_encode ( $_POST ) );
	file_put_contents ( $DevicePath . DS . "TicketRequest.serialized", serialize ( $_POST ) );
#	file_put_contents ( $DevicePath . DS . "TicketRequest.txt", $_POST );


	//
	//
	$FairPlayCertChain = $DeviceEncoded->getElementsByTagName('data')->item(1)->nodeValue;
	$FairPlaySignature = $DeviceEncoded->getElementsByTagName('data')->item(2)->nodeValue;


	//
	file_put_contents ( $DevicePath . DS . "FairPlayCertChain.der", $FairPlayCertChain );
	file_put_contents ( $DevicePath . DS . "FairPlaySignature.key", $FairPlaySignature );


	//
	$DeviceEncoded->save( $DevicePath . DS . "ActivationInfo.plist");
	$DeviceDecoded->save( $DevicePath . DS . "ActivationInfoXML.plist");


	//
	//
	$FairPlayCertChain_Der_Content = file_get_contents ( $DevicePath . DS . "FairPlayCertChain.der" );
	$FairPlayCertChain_Pem_Content = '-----BEGIN CERTIFICATE-----' . PHP_EOL . chunk_split ( base64_encode ( $FairPlayCertChain_Der_Content ), 64, PHP_EOL ) . '-----END CERTIFICATE-----' . PHP_EOL;


	//
	file_put_contents ( $DevicePath . DS . "FairPlayCertChain.pem", $FairPlayCertChain_Pem_Content );


	// Prepare ActivationInfoXML.plist File.
	//
	$ActivationInfoDEC = file_get_contents ( $DevicePath . DS . "ActivationInfoXML.plist" );
	$ActivationInfoDEC = $PParser->parse ( $ActivationInfoDEC );


	// Get And Store DeviceCertRequest Public Key.
	//
	$Certificate = base64_decode ( $DeviceCert );
	$Certificate_Details = openssl_pkey_get_details ( openssl_csr_get_public_key ( $Certificate ) );
	$Certificate_PublicKey = $Certificate_Details[ 'key' ];

	//
	file_put_contents ( $DevicePath . DS . "DeviceCert.csr", $Certificate );
	file_put_contents ( $DevicePath . DS . "DeviceCertPublic.key", $Certificate_PublicKey );


	// Extra
	//
	extract ( $ActivationInfoDEC );






	// This is an extremely needed check :).
	//
	$Check_iDevice = Check_iDevice ( $ProductType );
	$Check_iDevice_Type = Check_iDevice ( $ProductType, true );
	$Check_iDevice_Name = Check_iDevice ( $ProductType, true, true );


	//
	//
	if ( $Check_iDevice === true ) {

		$Msg->Info( "Check_iDevice = Look for SIMStatus\r\n", "AInfo" );
		$Has_SIM = true;
			
		if ( array_key_exists ( 'SIMStatus', get_defined_vars ( ) ) ) {

			$Msg->Info( "SIMStatus = Checked " . $SIMStatus, "AInfo B64" );

			if ( Check_SIMStatus ( $SIMStatus ) === true ) {

				$Msg->Info( "SIMStatus = Normal " . $SIMStatus, "AInfo B64" );
				$SIM_OK = true;

			} else {

				$Msg->Info( "SIMStatus = Warning " . $SIMStatus, "AInfo B64" );
				$SIM_OK = false;

			}

		} else {

			$Msg->Info( "SIMStatus = Error " . $SIMStatus, "AInfo" );
			$SIM_OK = false;
		}

	} else {

		$Msg->Info( "SIMStatus = Default SIM Status to Normal " . $SIMStatus, "AInfo B64" );
		$Has_SIM = false;
		$SIM_OK = false;
	}


	//
	//
	if ( ( $ProductType == "iPod1,1" )
			or ( $ProductType == "iPod2,1" )
			or ( $ProductType == "iPod3,1" )
			or ( $ProductType == "iPod4,1" )
			or ( $ProductType == "iPod5,1" )
//			or ( $ProductType == "iPhone3,1" )
//			or ( $ProductType == "iPhone3,2" )
//			or ( $ProductType == "iPhone3,3" )
			or ( $ProductType == "iPad2,1" )
			or ( $ProductType == "iPad2,2" )
			or ( $ProductType == "iPad2,3" )
			or ( $ProductType == "iPad2,4" ) ) {

		$Has_SIM = false;
	}



	// Get Device Type.
	//
	if ( $Check_iDevice_Name != null ) {

		$Msg->Info( "Check_iDevice_Name = Normal", "AInfo B64" );
		$iDeviceType = $Check_iDevice_Name;

	} else {

		$Msg->Info( "Check_iDevice_Name = Unknown", "AInfo B64" );
		$iDeviceType = "Unknown iDevice";
	}


	// Check SAM & Get Started :).
	//
	if ( $Has_SIM == true ) {

		require_once ( DEVICE_SERVICES . 'AInfoB64_Template.php' );
	}


	?>