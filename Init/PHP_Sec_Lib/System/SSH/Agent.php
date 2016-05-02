<?php
define ( 'SYSTEM_SSH_AGENTC_REQUEST_IDENTITIES', 11 );
define ( 'SYSTEM_SSH_AGENT_IDENTITIES_ANSWER', 12 );
define ( 'SYSTEM_SSH_AGENT_FAILURE', 5 );
define ( 'SYSTEM_SSH_AGENTC_SIGN_REQUEST', 13 );
define ( 'SYSTEM_SSH_AGENT_SIGN_RESPONSE', 14 );

class System_SSH_Agent_Identity
{
	
	var $key;
	
	var $key_blob;
	
	var $fsock;

	function System_SSH_Agent_Identity ( $fsock )
	{
		$this->fsock = $fsock;
	}

	function setPublicKey ( $key )
	{
		$this->key = $key;
		$this->key->setPublicKey ( );
	}

	function setPublicKeyBlob ( $key_blob )
	{
		$this->key_blob = $key_blob;
	}

	function getPublicKey ( $format = null )
	{
		return ! isset ( $format ) ? $this->key->getPublicKey ( ) : $this->key->getPublicKey ( $format );
	}

	function setSignatureMode ( $mode )
	{
	}

	function sign ( $message )
	{
		$packet = pack ( 'CNa*Na*N', SYSTEM_SSH_AGENTC_SIGN_REQUEST, strlen ( $this->key_blob ), $this->key_blob, strlen ( $message ), $message, 0 );
		$packet = pack ( 'Na*', strlen ( $packet ), $packet );
		if ( strlen ( $packet ) != fputs ( $this->fsock, $packet ) )
		{
			user_error ( 'Connection closed during signing' );
		}
		
		$length = current ( unpack ( 'N', fread ( $this->fsock, 4 ) ) );
		$type = ord ( fread ( $this->fsock, 1 ) );
		if ( $type != SYSTEM_SSH_AGENT_SIGN_RESPONSE )
		{
			user_error ( 'Unable to retreive signature' );
		}
		
		$signature_blob = fread ( $this->fsock, $length - 1 );
		return substr ( $signature_blob, strlen ( 'ssh-rsa' ) + 12 );
	}
}

class System_SSH_Agent
{

	var $fsock;

	function System_SSH_Agent ( )
	{
		switch ( true )
		{
			case isset ( $_SERVER [ 'SSH_AUTH_SOCK' ] ) :
				$address = $_SERVER [ 'SSH_AUTH_SOCK' ];
				break;
			case isset ( $_ENV [ 'SSH_AUTH_SOCK' ] ) :
				$address = $_ENV [ 'SSH_AUTH_SOCK' ];
				break;
			default :
				user_error ( 'SSH_AUTH_SOCK not found' );
				return false;
		}
		
		$this->fsock = fsockopen ( 'unix://' . $address, 0, $errno, $errstr );
		if ( ! $this->fsock )
		{
			user_error ( "Unable to connect to ssh-agent (Error $errno: $errstr)" );
		}
	}

	function requestIdentities ( )
	{
		if ( ! $this->fsock )
		{
			return array ();
		}
		
		$packet = pack ( 'NC', 1, SYSTEM_SSH_AGENTC_REQUEST_IDENTITIES );
		if ( strlen ( $packet ) != fputs ( $this->fsock, $packet ) )
		{
			user_error ( 'Connection closed while requesting identities' );
		}
		
		$length = current ( unpack ( 'N', fread ( $this->fsock, 4 ) ) );
		$type = ord ( fread ( $this->fsock, 1 ) );
		if ( $type != SYSTEM_SSH_AGENT_IDENTITIES_ANSWER )
		{
			user_error ( 'Unable to request identities' );
		}
		
		$identities = array ();
		$keyCount = current ( unpack ( 'N', fread ( $this->fsock, 4 ) ) );
		for ( $i = 0; $i < $keyCount; $i ++ )
		{
			$length = current ( unpack ( 'N', fread ( $this->fsock, 4 ) ) );
			$key_blob = fread ( $this->fsock, $length );
			$length = current ( unpack ( 'N', fread ( $this->fsock, 4 ) ) );
			$key_comment = fread ( $this->fsock, $length );
			$length = current ( unpack ( 'N', substr ( $key_blob, 0, 4 ) ) );
			$key_type = substr ( $key_blob, 4, $length );
			switch ( $key_type )
			{
				case 'ssh-rsa' :
					if ( ! class_exists ( 'Crypt_RSA' ) )
					{
						include_once '/../Crypt/RSA.php';
					}
					$key = new Crypt_RSA ( );
					$key->loadKey ( 'ssh-rsa ' . base64_encode ( $key_blob ) . ' ' . $key_comment );
					break;
				case 'ssh-dss' :
					break;
			}
			if ( isset ( $key ) )
			{
				$identity = new System_SSH_Agent_Identity ( $this->fsock );
				$identity->setPublicKey ( $key );
				$identity->setPublicKeyBlob ( $key_blob );
				$identities [ ] = $identity;
				unset ( $key );
			}
		}
		
		return $identities;
	}
}
