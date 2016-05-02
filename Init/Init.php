<?php


	//
	//
	require_once ( 'Init.Core.php' );
	require_once ( 'Init.Directory.php' );
	require_once ( 'Init.Config.php' );
	require_once ( 'Init.DoulCi.php' );
	require_once ( 'Init.Apple.php' );
	require_once ( 'Init.Agent.php' );
	require_once ( 'Init.Meta.php' );
	require_once ( 'Init.PKI.php' );


	//
	//
	require_once ( 'Functions/Functions.php' );
	require_once ( 'Functions/Curl.php' );
	require_once ( 'Functions/File.php' );
	require_once ( 'Functions/Plist.php' );
	require_once ( 'Functions/AccountToken.php' );
	require_once ( 'Functions/Signature.php' );
	require_once ( 'Functions/IP.php' );
	require_once ( 'Functions/Utils.php' );


	//
	//
	require_once ( 'Classes/PlistParser.php' );
	require_once ( 'Classes/ShowMsg.php' );

	//
	//
	include ( 'PHP_SEC_LIB/File/X509.php' );
	include ( 'PHP_SEC_LIB/Crypt/RSA.php' );
	

	//
	//
	$PParser = new PlistParser ( );
	$Msg =  new ShowMsg();


	?>