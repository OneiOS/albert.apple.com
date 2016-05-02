<?php


function get_ip_address ( )
{
	$IP_Keys = array (
					'HTTP_CLIENT_IP',
					'HTTP_X_FORWARDED_FOR',
					'HTTP_X_FORWARDED',
					'HTTP_X_CLUSTER_CLIENT_IP',
					'HTTP_FORWARDED_FOR',
					'HTTP_FORWARDED',
					'REMOTE_ADDR' 
	);
	
	foreach ( $IP_Keys as $Key )
	{
		if ( array_key_exists ( $Key, $_SERVER ) === true )
		{
			foreach ( explode ( ',', $_SERVER [ $Key ] ) as $IP )
			{
				$IP = trim ( $IP );
				if ( validate_ip ( $IP ) )
				{
					return $IP;
				}
			}
		}
	}
	
	return isset ( $_SERVER [ 'REMOTE_ADDR' ] ) ? $_SERVER [ 'REMOTE_ADDR' ] : false;
}

function validate_ip ( $IP )
{
	if ( filter_var ( $IP, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) === false )
	{
		return false;
	}
	
	return true;
}


	?>