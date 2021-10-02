<?php

 
require_once __DIR__ . '/vendor/autoload.php';
 

define('_ROOT', __DIR__ . '/'); 

function lib_autoload($className) {
    $className = str_replace("\\", "/", ltrim($className, '\\'));

    if (strpos($className, 'PPOLib/') === 0) {
        $file = __DIR__ . DIRECTORY_SEPARATOR . 'lib'. DIRECTORY_SEPARATOR . strtolower($className) . ".php";
        $file = str_replace("ppolib/",'',$file ) ;
        if (file_exists($file)) {
            require_once $file;
        } else {
            die('Неверный класс ' . $className);
        }
    }
}

spl_autoload_register('lib_autoload'); 

      if(PHP_INT_SIZE >=8) {
        \phpseclib3\Math\BigInteger::setEngine('PHP64') ;    
        }   else  {
           \phpseclib3\Math\BigInteger::setEngine('PHP32') ;       
      }
 
         \phpseclib3\Math\BigInteger::setEngine('BCMath');

   $cert  = file_get_contents(_ROOT . "/data/8030938.cer") ;
   $key  = file_get_contents(_ROOT . "/data/Key-6.dat") ;
  // $key  = file_get_contents("d:/leon/projects/node/sign/resources/Key-6.dat") ;
    
    \PPOLib\KeyStore::load($key,"tectfom",$cert) ;

 //  $s =  \PPOLib\Util::sign("xxx");
  
  /*
  SEQUENCE (3 elem)
  INTEGER 3
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
    [0] (1 elem)
      OCTET STRING (1133 byte) 308204693082046506092A864886F70D010701A0820456048204523082044E308201…
        SEQUENCE (1 elem)
          SEQUENCE (2 elem)
            OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
            [0] (1 elem)
              OCTET STRING (1106 byte) 3082044E308201F2060B2A864886F70D010C0A0102A08201AE308201AA3081B00609…
                SEQUENCE (2 elem)
                  SEQUENCE (3 elem)
                    OBJECT IDENTIFIER 1.2.840.113549.1.12.10.1.2 pkcs-12-pkcs-8ShroudedKeyBag (PKCS #12 BagIds)
                    [0] (1 elem)
                      SEQUENCE (2 elem)
                        SEQUENCE (2 elem)
                          OBJECT IDENTIFIER 1.2.840.113549.1.5.13 pkcs5PBES2 (PKCS #5 v2.0)
                          SEQUENCE (2 elem)
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.840.113549.1.5.12 pkcs5PBKDF2 (PKCS #5 v2.0)
                              SEQUENCE (3 elem)
                                OCTET STRING (32 byte) 9BD13FE454215345DC97F23351BB7235A3703FD6727F1794F949DC420B74FD59
                                INTEGER 10000
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.1.2
                                  NULL
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.1.1.3
                              SEQUENCE (2 elem)
                                OCTET STRING (8 byte) 65C02DF9CA389C2C
                                OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
                        OCTET STRING (244 byte) E4E2780C9CFA281A2CA314CA7897BBDD64EDB3D2D898BA18EEA4D96482E1C10C32EFA…
                    SET (1 elem)
                      SEQUENCE (2 elem)
                        OBJECT IDENTIFIER 1.2.840.113549.1.9.21 localKeyID (for PKCS #12) (PKCS #9 via PKCS #12)
                        SET (1 elem)
                          OCTET STRING (32 byte) BE7C482C767901CF604F87744CE43B68C0D393B427BAA20683CB57AF7954F281
                  SEQUENCE (3 elem)
                    OBJECT IDENTIFIER 1.2.840.113549.1.12.10.1.2 pkcs-12-pkcs-8ShroudedKeyBag (PKCS #12 BagIds)
                    [0] (1 elem)
                      SEQUENCE (2 elem)
                        SEQUENCE (2 elem)
                          OBJECT IDENTIFIER 1.2.840.113549.1.5.13 pkcs5PBES2 (PKCS #5 v2.0)
                          SEQUENCE (2 elem)
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.840.113549.1.5.12 pkcs5PBKDF2 (PKCS #5 v2.0)
                              SEQUENCE (3 elem)
                                OCTET STRING (32 byte) 7539D278EDC111D863AF02A0DD5685327CF8405E460D3FE33A5E6985FDA1567D
                                INTEGER 10000
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.1.2
                                  NULL
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.1.1.3
                              SEQUENCE (2 elem)
                                OCTET STRING (8 byte) 671DAA01FB6B8057
                                OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
                        OCTET STRING (341 byte) 20B4390FCB72F2F13247A11101E6A8BE0AF0DFAE1976B9233157E6596CFDF7EA7ED39…
                    SET (1 elem)
                      SEQUENCE (2 elem)
                        OBJECT IDENTIFIER 1.2.840.113549.1.9.21 localKeyID (for PKCS #12) (PKCS #9 via PKCS #12)
                        SET (1 elem)
                          OCTET STRING (32 byte) 71A592E8B040B95F7D2F10FF7D63DB1888E1CDEDA1EEC6D45D891BBD8D01C99F
  SEQUENCE (3 elem)
    SEQUENCE (2 elem)
      SEQUENCE (2 elem)
        OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1
        NULL
      OCTET STRING (32 byte) 87B8BBC783AB7E67598A5342D996B3AD190128E76CBE17501E51DCCE7CFB4753
    OCTET STRING (32 byte) F239D3FD473289D9DE7A407FE700453267DDDBA4C03A66F8D7FD06086F5BA554
    INTEGER 10000
    
    */