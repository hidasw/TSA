<?php
/*
// File name   : tsa.php
// Version     : 1.1
// Last Update : 01/05/2024
// Author      : Hida - https://github.com/hidasw
// License     : GPL-3.0 license
*/
class tsa {
  public $policy;
  public $hashAlgorithm = 'sha256';
  public $serial = '0';
  public $signerCert;
  public $signerPkey;
  public $extracerts = array();
  
  public static function get_cert($certin) { // Read x.509 DER/PEM Certificate and return DER encoded x.509 Certificate
    if($rsccert = @openssl_x509_read ($certin)) {
      openssl_x509_export ($rsccert, $cert);
      //openssl_x509_free ($rsccert);
      return self::x509_pem2der($cert);
    } else {
      $pem = @self::x509_der2pem($certin);
      if($rsccert = @openssl_x509_read ($pem)) {
        openssl_x509_export ($rsccert, $cert);
        return self::x509_pem2der($cert);
      } else {
        return false;
      }
    }
  }
  
  public static function hashAlg2hex($alg, $reverse=false) {
    $hexOidHashAlgos = array(
                            'md2'=>'2a864886f70d0202',
                            'md4'=>'2a864886f70d0204',
                            'md5'=>'2a864886f70d0205',
                            'sha' => '2b0e030212',
                            'sha1'=>'2b0e03021a',
                            'sha224'=>'608648016503040204',
                            'sha256'=>'608648016503040201',
                            'sha384'=>'608648016503040202',
                            'sha512'=>'608648016503040203',
                            'md2WithRSAEncryption' => '2a864886f70d010102',
                            'md4WithRSAEncryption' => '2a864886f70d010103',
                            'md5withrsa' => '2b0e030203',
                            'md5WithRSAEncryption' => '2a864886f70d010104',
                            'shaWithRSAEncryption' => '2b0e03020f',
                            'sha1WithRSAEncryption' => '2a864886f70d010105',
                            'sha224WithRSAEncryption' => '2a864886f70d01010e',
                            'sha256WithRSAEncryption' => '2a864886f70d01010b',
                            'sha384WithRSAEncryption' => '2a864886f70d01010c',
                            'sha512WithRSAEncryption' => '2a864886f70d01010d'
                            );
    if($reverse) {
      return current(array_keys($hexOidHashAlgos, $alg));
    }
    if(@array_key_exists($alg, $hexOidHashAlgos)) {
      return $hexOidHashAlgos[$alg];
    }
  }
  
//============================================================+
// function    : oid2hex
// Version     : 1.1
// Begin       : 26/03/2009
// Last Update : 30/04/2024
// Author      : Hida - https://github.com/hidasw
// License     : GPL-3.0 license
// Description : Convert oid number to hexadecimal form
// Changes     : Tuesday, 30 April 2024 08:25:52 Simplified from 3 functions to just one function
// -------------------------------------------------------------------
  public static function oid2hex($oid) {
    if(!preg_match("~^(?!\.)[0-9.]*$(?<!\.)~", $oid)) { // only allow dot and number
      return false;
    }
    $arr = explode(".", trim($oid, "."));
    if(count($arr)<2) {
      return false;
    }
    $i = 0;
    $ret = false;
    foreach($arr as $val) {
      if($i == 0) {
        if($val <= 2) {
          $add = $val*40;
        }
      }
      $functG=false;
      if($i == 1) {
        if($val >= 48) {
          $functG=true;
          $dec=$val+80;
        } else {
          $val = $val+$add;
        }
      }
      if($i > 1) {
        if($val >= 128) {
          $functG=true;
          $dec=$val;
        }
      }
      if($functG) {
        $hex = array();
        $ix=0;
        while($dec != $dec%128) {
          $hida = $dec%128;
          if($ix != 0) { // not first loop
            $hida = $hida+128;
          }
          $dec = floor($dec/128);
          $hex[] = str_pad(dechex($hida), 2, "0", STR_PAD_LEFT);
          if($dec == $dec%128) { // end loop
            $hida = $dec+128;
            $hex[] = str_pad(dechex($hida), 2, "0", STR_PAD_LEFT);
          }
          $ix++;
        }
        $ret .= implode('',array_reverse($hex));
      } else {
        $ret = str_pad(dechex($val), 2, "0", STR_PAD_LEFT);
      }
      $i++;
    }
    return $ret;
  }
  
  public static function x509_der2pem($der_cert) { // This function convert x509 der certificate to x509 PEM
    $x509_pem = "-----BEGIN CERTIFICATE-----\r\n";
    $x509_pem .= chunk_split(base64_encode($der_cert),64);
    $x509_pem .= "-----END CERTIFICATE-----\r\n";
    return $x509_pem;
  }
  
  public static function x509_get_pubkeys($cert) {
    $result = array();
    if($cert = self::get_cert($cert)) {
    $hex= bin2hex($cert);
    $Certificate = asn1::parse($hex);
    $Certificate = $Certificate[0];
    $TBSCertificate = $Certificate[0];
    $TBSCertificate_signature = $TBSCertificate[2];
    $TBSCertificate_subjectPublicKeyInfo = $TBSCertificate[6];
    $TBSCertificate_subject = $TBSCertificate[5]['hexdump'];
    $TBSCertificate_issuer = $TBSCertificate[3];
    $TBSCertificate_serial = $TBSCertificate[1];
    $pub_key = hex2bin(substr($TBSCertificate_subjectPublicKeyInfo[1]['value'], 2));
    $subj_key = hex2bin($TBSCertificate_subject);
    $issuerName = hex2bin($TBSCertificate_issuer['hexdump']);
    switch(strtoupper($TBSCertificate_signature[0]['hexdump'])) {
      case '06092A864886F70D01010D' : $alg = 'sha512'; break;
      case '06092A864886F70D01010C' : $alg = 'sha384'; break;
      case '06092A864886F70D01010B' : $alg = 'sha256'; break;
      case '06092A864886F70D01010E' : $alg = 'sha224'; break;
      case '06092A864886F70D010105' : $alg = 'sha1'; break;
      case '06092A864886F70D010104' : $alg = 'md5'; break;
    }
    $result['hash'] = $alg;
    $result['issuerName'] = $TBSCertificate_issuer['hexdump'];
    $result['issuerNameHash'] = hash('sha1', $issuerName);
    $result['subjectName'] = $TBSCertificate_subject;
    $result['serialNumber'] = $TBSCertificate_serial['value'];
    $result['subjectNameHash'] = hash('sha1', $subj_key);
    $result['subjectKeyHash'] = hash('sha1', $pub_key);
    return $result;
    }
  }
  
  private static function x509_pem2der($pem) {  // This function convert x509 pem certificate to x509 der
    $x509_der = false;
    if($x509_res = @openssl_x509_read($pem)) {
      openssl_x509_export ($x509_res,  $x509_pem);
      //openssl_x509_free ($x509_res);

      $arr_x509_pem = explode("\n", $x509_pem);
      $numarr = count($arr_x509_pem);
      $i=0;
      $cert_pem = false;
      foreach($arr_x509_pem as $val)  {
        if($i > 0 && $i < ($numarr-2))  {
          $cert_pem .= $val;
        }
        $i++;
      }
      $x509_der = base64_decode($cert_pem);
    }
    return $x509_der;
  }
  static function parse_query($binreq, &$err=false) {
    if(!$p = asn1::parse(bin2hex($binreq))) {
      $err = "tsq request asn1::parse fail";
      return false; 
    }
    if(@$p[0]['type'] !== '30') { return false; }
    $tsq = array();
    foreach($p[0] as $key=>$value) {
      if(is_numeric($key)) {
        if($value['type'] == '02' && !array_key_exists('version', $tsq)) {
          $tsq['version'] = $value['value'];
          continue;
        } else
        if($value['type'] == '30') {
          foreach($value as $messageImprintK=>$messageImprintV) {
            if(is_numeric($messageImprintK)) {
              if($messageImprintV['type'] == '30') {
                $messageImprint['digestAlgorithm'] = $messageImprintV[0]['value_hex'];
              }
              if($messageImprintV['type'] == '04') {
                $messageImprint['digestContent'] = $messageImprintV['value_hex'];
              }
            }
            
          }
          $tsq['messageImprint'] = $messageImprint;
        }
        if($value['type'] == '02') {
          $tsq['nonce'] = $value['value'];
        }
        if($value['type'] == '01') {
          $tsq['certReq'] = $value['value_hex'];
        }
        if($value['type'] == 'a0') {
          $tsq['extensions'] = $value['hexdump'];
        }
      }
    }
    $arrModel['version'] = '';
    $arrModel['messageImprint']['digestAlgorithm'] = '';
    $arrModel['messageImprint']['digestContent'] = '';
    $differ=array_diff_key($arrModel,$tsq);
    if(count($differ) == 0) {
      $differ=array_diff_key($arrModel['messageImprint'], $tsq['messageImprint']);
      if(count($differ) > 0) {
        $err = "tsq request parse fail";
        foreach($differ as $key=>$val) {
          $err = "tsq request field messageImprint->$key not exists";
        }
        return false;
      }
    } else {
      echo "tsq request parse fail!!";
      foreach($differ as $key=>$val) {
        $err = "tsq request field $key not exists";
      }
      return false;
    }
    return $tsq;
  }
  
  function reply($req, &$err=false) {
    if(!$this->hashAlg2hex($this->hashAlgorithm)) {
      $err ="not support hash alg \"".$this->hashAlgorithm."\"!";
      return false;
    }
    if(!self::get_cert($this->signerCert)) {
      $err ="signerCert error!";
      return false;
    }
    if(!openssl_pkey_get_private($this->signerPkey)) {
      $err = "signerPkey error!";
      return false;
    }
    if(!$parse_query = $this->parse_query($req, $err)) {
      $err = "failed to parse request from {$_SERVER['REMOTE_ADDR']} ({$_SERVER['HTTP_HOST']}) \"{$_SERVER['HTTP_USER_AGENT']}\"";
      return false;
    }
    if(!$signerCertId = $this->x509_get_pubkeys($this->signerCert)) {
      $err = "x509_get_pubkeys failed On ".__FILE__."(".__LINE__.")";
      return false;
    }
    $reqNonce = (array_key_exists('nonce', $parse_query))?$parse_query['nonce']:false;
    $utcdate = gmdate("ymdHis");
    $gendate = gmdate("YmdHis");
    $TimeStamp = $gendate;
    $microtime = microtime();
    $TimeStampAccuracy =  asn1::seq( // add @ 07:11 Esuk Kamis 16 Juli 2009
                            asn1::int('21').
                            asn1::other('80', str_pad(dechex('999'), strlen(dechex('999'))+1, "0", STR_PAD_LEFT),0).
                            asn1::other('81', str_pad(dechex('999'), strlen(dechex('999'))+1, "0", STR_PAD_LEFT),0)
                          );
    $TSTInfo =  asn1::seq(
                  asn1::int("1"). //version
                    asn1::obj($this->oid2hex($this->policy)).
                      asn1::seq(
                        asn1::seq(
                          asn1::obj($parse_query['messageImprint']['digestAlgorithm']).
                          '0500'
                        ).
                        asn1::oct($parse_query['messageImprint']['digestContent'])
                      ).
                  asn1::int($this->serial).
                  asn1::gtime($TimeStamp).
                  $TimeStampAccuracy.
                  asn1::int($reqNonce)
                );
    $TSTInfo_hash = hash($this->hashAlgorithm, hex2bin($TSTInfo)); // custom hash dr DER encoding TSTinfo
    $certSignerFingerprint = hash('sha1', $this->get_cert($this->signerCert)); // sha1 hash dr DER encoding sertifikat TSA
    $signedinfo = asn1::seq(
                    '06092A864886F70D010903'. //OBJ_pkcs9_contentType.
                    asn1::set(
                      '060B2A864886F70D0109100104' //OBJ_id_smime_ct_TSTInfo
                    )
                  ).
                  asn1::seq(
                    '06092A864886F70D010905'. //OBJ_pkcs9_signingTime.
                    asn1::set(
                      asn1::utime($utcdate)
                    )
                  ).
                  asn1::seq(
                    '06092A864886F70D010904'. //OBJ_pkcs9_messageDigest.
                    asn1::set(
                      asn1::oct($TSTInfo_hash)
                    )
                  ).
                  asn1::seq(
                    '060B2A864886F70D010910020C'. //OBJ_id_smime_aa_signingCertificate.
                    asn1::set(
                      asn1::seq(
                        asn1::seq(
                          asn1::seq(
                            asn1::oct($certSignerFingerprint).
                              asn1::seq(
                                asn1::seq(
                                  asn1::expl("4", 
                                    $signerCertId['issuerName']
                                  )
                                ).
                              asn1::int($signerCertId['serialNumber'])
                            )
                          )
                        )
                      )
                    )
                  );
    $signedinfo_hash =  hash($this->hashAlgorithm, hex2bin(asn1::set(
                                                            $signedinfo
                                                          )
                                                  )
                       );
    $to_encrypt = asn1::seq(
                    asn1::seq(
                      asn1::obj($this->hashAlg2hex($this->hashAlgorithm)).
                      '0500'
                    ).
                    asn1::oct($signedinfo_hash)
                  );
    if(!openssl_private_encrypt(hex2bin($to_encrypt), $crypted, $this->signerCert)) {
      $err = "Failed to signing\n".__FILE__."(".__LINE__.")";
      return false;
    }
    $extraCerts = false;
    if(count($this->extracerts)>0) {
      foreach($this->extracerts as $extcrt) {
        $extraCerts .= self::get_cert($extcrt);
      }
    }
    $embedTsaCerts = false;
    if(array_key_exists('certReq', $parse_query)) {
      $embedTsaCerts = asn1::expl("0",
                         bin2hex($this->get_cert($this->signerCert)).
                         bin2hex($extraCerts)
                       );
    }
    $tst =  asn1::seq(
              asn1::seq(
                asn1::int("0").
                  asn1::seq(
                    asn1::utf8("TimeStamp by Php")
                  )
              ).
              asn1::seq(
                  '06092A864886F70D010702'. //OBJ_pkcs7_signed.
                  asn1::expl("0",
                    asn1::seq(
                      asn1::int("3").
                      asn1::set(
                        asn1::seq(
                          asn1::obj($this->hashAlg2hex($this->hashAlgorithm)).
                          '0500'
                        )
                      ).
                      asn1::seq(
                        '060B2A864886F70D0109100104'. //OBJ_id_smime_ct_TSTInfo.
                        asn1::expl("0",
                           asn1::oct($TSTInfo)
                        )
                      ).
                      $embedTsaCerts.
                      asn1::set(
                        asn1::seq(
                          asn1::int("1").
                          asn1::seq(
                            $signerCertId['issuerName'].
                            asn1::int($signerCertId['serialNumber'])
                          ).
                          asn1::seq(
                            asn1::obj($this->hashAlg2hex($this->hashAlgorithm)).
                            '0500'
                          ).
                          asn1::expl("0",
                            $signedinfo
                          ).
                          asn1::seq(
                            '06092A864886F70D010101'. //OBJ_rsaEncryption.
                            '0500' //OBJ_null
                          ).
                          asn1::oct(
                            bin2hex($crypted) // Hasil enkripsi (TSA signature)
                          )
                        )
                      )
                    )
                  )
              )
            );
    return hex2bin($tst);
  }
}
?>