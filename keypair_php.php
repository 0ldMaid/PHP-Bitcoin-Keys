<?php



	//Use base 256
	define('MAX_BASE', 256);

	//Force Either BCMATH or GMP, Autodetected otherwise, prefers GMP
	//if(!defined('USE_EXT')) define ('USE_EXT', 'BCMATH');
	//if(!defined('USE_EXT')) define ('USE_EXT', 'GMP');

	include 'autoload.inc.php';
	include 'classes/PHPECC.class.php';
	include 'classes/SECurve.class.php';

	$keypair = PHPECC::hex_keypair_genorate();


	//echo $keypair['private'];
	//echo "<br>";
	//echo "<br>";
	//echo $keypair['public'];



	//echo "<br>";

	$prvKey = $keypair['private'];
	//$prvKey = "1184CD2CDD640CA42CFC3A091C51D549B2F016D454B2774019C2B2D2E08529FD";

	//echo "Private Key";
	//echo "<br>";

	$xstep1 = "80" . $prvKey;

	//echo "step 1 " . $prvKey;
	//echo "<br>";

	$xstep2 = hash("sha256", hexStringToByteString($xstep1));

	//echo "Step 2: " . $xstep2;
	//echo "<br>";

	$xstep3 = hash("sha256", hexStringToByteString($xstep2));

	//echo "Step 3: " . $xstep3;
	//echo "<br>";

	$xstep4 = substr($xstep3, 0, 8);

	//echo "Step 4: " . $xstep4;
	//echo "<br>";

	$xstep5 = $xstep1.strtoupper($xstep4);

	//echo "Step 5: " . $xstep5;
	//echo "<br>";

	$xstep6 = bc_base58_encode(bc_hexdec($xstep5));
	//echo "WIF Private Key ".$xstep6;

	$PRIVATE_KEY = $xstep6;

	//^^^^^^THIS IS THE PRIVATE KEY YOU WANT
	//********************************************************************************************************




	//echo "<br>";
	//echo "<br>";
	//echo "<br>";
	//echo "Public Key";
	//echo "<br>";
	
	$publickey = $keypair['public'];
	//$publickey = '04bb0589ef895d0f4e60d3de752dcc54cc626cf55573e750dd95ca66b564932bb7e22577bc8cef0a86e3d8d61f2ab120cb02840f9e618ca939c2eb818ff4fbeb93';

	//echo "step1 ".$publickey."<br>";

	$step1 = hexStringToByteString($publickey);

	// step 2

	$step2 = hash("sha256", $step1);
	//echo "step2 ".$step2."<br>";

	// step 3

	$step3 = hash('ripemd160', hexStringToByteString($step2));
	//echo "step3 ".$step3."<br>";

	// step 4

	$step4 = "00".$step3;
	//echo "step4 ".$step4."<br>";

	// step 5

	$step5 = hash("sha256", hexStringToByteString($step4));
	//echo "step5 ".$step5."<br>";

	// step 6

	$step6 = hash("sha256", hexStringToByteString($step5));
	//echo "step6 ".$step6."<br>";

	// step 7

	$checksum = substr($step6,0,8);
	//echo "step7 ".$checksum."<br>";

	// step 8

	$step8 = $step4.$checksum;
	//echo "step8 ".$step8."<br>";

	//step 9

	$step9 = "1".bc_base58_encode(bc_hexdec($step8));
	//echo "Public Key ".$step9."<br><br>";

	$PUBLIC_KEY = $step9;

	//^^^^^^THIS IS THE PUBLIC KEY YOU WANT
	//********************************************************************************************************







function hexStringToByteString($hexString){
    $len=strlen($hexString);

    $byteString="";
    for ($i=0;$i<$len;$i=$i+2){
        $charnum=hexdec(substr($hexString,$i,2));
        $byteString.=chr($charnum);
    }

return $byteString;
}









function bc_arb_encode($num, $basestr) {
    if( ! function_exists('bcadd') ) {
        Throw new Exception('You need the BCmath extension.');
    }

    $base = strlen($basestr);
    $rep = '';

    while( true ){
        if( strlen($num) < 2 ) {
            if( intval($num) <= 0 ) {
                break;
            }
        }
        $rem = bcmod($num, $base);
        $rep = $basestr[intval($rem)] . $rep;
        $num = bcdiv(bcsub($num, $rem), $base);
    }
    return $rep;
}

function bc_arb_decode($num, $basestr) {
    if( ! function_exists('bcadd') ) {
        Throw new Exception('You need the BCmath extension.');
    }

    $base = strlen($basestr);
    $dec = '0';

    $num_arr = str_split((string)$num);
    $cnt = strlen($num);
    for($i=0; $i < $cnt; $i++) {
        $pos = strpos($basestr, $num_arr[$i]);
        if( $pos === false ) {
            Throw new Exception(sprintf('Unknown character %s at offset %d', $num_arr[$i], $i));
        }
        $dec = bcadd(bcmul($dec, $base), $pos);
    }
    return $dec;
}


// base 58 alias
function bc_base58_encode($num) {   
    return bc_arb_encode($num, '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
}
function bc_base58_decode($num) {
    return bc_arb_decode($num, '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz');
}

//hexdec with BCmath
function bc_hexdec($num) {
    return bc_arb_decode(strtolower($num), '0123456789abcdef');
}
function bc_dechex($num) {
    return bc_arb_encode($num, '0123456789abcdef');
}





?>