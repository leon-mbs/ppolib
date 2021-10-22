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

 

   //  $cert  = file_get_contents(_ROOT . "/data/oldkey/8030938.cer") ;
  //   $key  = file_get_contents(_ROOT . "/data/oldkey/Key-6.dat") ;
  //    \PPOLib\KeyStore::load($key,"tectfom",$cert ) ;
    $cert  = file_get_contents(_ROOT . "/data/newkey/EU.cer") ;
     $key  = file_get_contents(_ROOT . "/data/newkey/Key-6.dat") ;
   
   
     $cert =    \PPOLib\Cert::load($cert) ;
     \PPOLib\KeyStore::load($key,"123qwe",$cert ) ;

     

 //  $s =  \PPOLib\Util::sign("xxx");
  
  
   $k =  \PPOLib\Field::fromString('abcd1',16) ;
   $d =  \PPOLib\Field::fromString('dcba2',16) ;

  $f=  $k->mul($d) ;
    $f = $f->add(\PPOLib\Field::get1()) ; 
  $fh = $f->toString(16) ;
  
  $rc = $f->div($k) ;
  
  $rch = $rc[0]->toString(16);
  
  
   $fh=null;
  
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
                                OCTET STRING (32 byte) 370A07F3387EFCB41860392A340A26493F2FCA653BF5DABB2CFD0EB63CF5D496
                                INTEGER 10000
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.1.2
                                  NULL
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.1.1.3
                              SEQUENCE (2 elem)
                                OCTET STRING (8 byte) 5313536DFE48265C
                                OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
                        OCTET STRING (244 byte) 4280DF7BC61960E4FB9D0D5DC0D562FF1DBCBA361BD2D60B9F147B555BA4E3ADBB0F7…
                    SET (1 elem)
                      SEQUENCE (2 elem)
                        OBJECT IDENTIFIER 1.2.840.113549.1.9.21 localKeyID (for PKCS #12) (PKCS #9 via PKCS #12)
                        SET (1 elem)
                          OCTET STRING (32 byte) E1B13ED5B3BD75DE937920589BF2C21EB6C3BC45082079C43469905B0D81780D
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
                                OCTET STRING (32 byte) AA5990D2EB4667E4D45C90A6C4317D6959B25553B1163D2EA4FF9C6907C0661C
                                INTEGER 10000
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.1.2
                                  NULL
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.1.1.3
                              SEQUENCE (2 elem)
                                OCTET STRING (8 byte) 0F29DFEAE4B14DEB
                                OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
                        OCTET STRING (341 byte) 585C235EFDE5BDEA97BD8AA7F589070109F57390448B564EB92757318BFF52E55F93F…
                    SET (1 elem)
                      SEQUENCE (2 elem)
                        OBJECT IDENTIFIER 1.2.840.113549.1.9.21 localKeyID (for PKCS #12) (PKCS #9 via PKCS #12)
                        SET (1 elem)
                          OCTET STRING (32 byte) 6042348D87A133FC90280E1F868AE947BCDBFA344EEA6646B1A54CBD982B4D2B
  SEQUENCE (3 elem)
    SEQUENCE (2 elem)
      SEQUENCE (2 elem)
        OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1
        NULL
      OCTET STRING (32 byte) 504CAE132DBDC9BDDB5F223EA15D732AC5EBFF2789B4370B528FAD71B7179AC0
    OCTET STRING (32 byte) B5CE07211D4572A9E599B13A0F79E1E2DF5A8BF158FFBF98CC9305B8EBFFAD40
    INTEGER 10000

    
    */