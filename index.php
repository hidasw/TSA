<?php
/*
// File name   : index.php
// Version     : 1.1
// Last Update : 01/05/2024
// Author      : Hida - https://github.com/hidasw
// License     : GPL-3.0 license
*/
if(strpos($_SERVER['HTTP_ACCEPT'], 'text/html') !== false) {
  include 'landing.php';
  exit;
}

require 'asn1.php';
include 'tsa.php';
$tsa = new tsa;

$extracertsdir=realpath('certs/extracerts');
if ($handle = opendir($extracertsdir)) {
  while (false !== ($entry = readdir($handle))) {
    $file=$extracertsdir."/".$entry;
    if (is_file($file)) {
      $filect = file_get_contents($file);
      if($extracerts=tsa::get_cert($filect)) {
       $tsa->extracerts[] = $extracerts;
      }
    }
  }
  closedir($handle);
}

$req = file_get_contents("php://input");
$tsa->policy = '2.16.840.1.113569.1.2.46.7';
$tsa->serial = '111';
$tsa->hashAlgorithm = 'sha256';
$signer = file_get_contents('certs/tsa.pem');
$tsa->signerCert = $signer;
$tsa->signerPkey = $signer;
if(!$response = $tsa->reply($req, $err)) {
  header($_SERVER['SERVER_PROTOCOL'] . ' 500 Internal Server Error', true, 500);
  $h = fopen('err.log','a');
  fwrite($h, date("Y/m/d H:i:s")."     ".$err."\n");
  fclose($h);
  exit;
}
echo $response;
?>