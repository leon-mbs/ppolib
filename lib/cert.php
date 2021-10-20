<?php
 
  namespace   PPOLib  ;
 
 
 use \PPOLib\Util ;
 
 
 
 class Cert {
    
 
 
    private $_publickey;
    
    public  static function load($cert) {
           
         
      
          $c = new  Cert();
          
          $seq = \ASN1\Type\Constructed\Sequence::fromDER($cert) ;
          $seq  =    $seq->at(0)->asSequence() ;

      
         $serial = $seq->at(1)
            ->asInteger()
            ->number();
         $algo = $seq->at(2)->asSequence()->at(0)->asObjectIdentifier()->oid();  
         $pki = $seq->at(6)->asSequence();
         
         $algo =$pki->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid();  
         $curveparam =$pki->at(0)->asSequence()->at(1)->asSequence()->at(0);  
         $curve = new Curve($curveparam,true) ;
         
         $pkey =$pki->at(1)->asBitString()->string() ;
         $a = Util::bstr2array($pkey) ;
         $a = array_slice($a,2) ; 
         $a = array_reverse($a) ; 
      
         
         $p= Field::fromString(Util::array2hex($a),16,$curve) ;
  
         $c->_publickey  = $curve->expand($p) ;
         
        
         return $c;
      
    }

    public function getPub(){
     
        
       return  $this->_publickey;
    }
    
 }
    

 /*
 SEQUENCE (3 elem)
  SEQUENCE (8 elem)
    [0] (1 elem)
      INTEGER 2
    INTEGER (159 bit) 507450138549618503925218067929507259826959972864
    SEQUENCE (1 elem)
      OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
    SEQUENCE (6 elem)
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
          UTF8String Інформаційно-довідковий департамент ДПС
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
          UTF8String Управління (центр) сертифікації ключів ІДД ДПС
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
          UTF8String КНЕДП - ІДД ДПС
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.5 serialNumber (X.520 DN component)
          UTF8String UA-43174711-2019
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
          PrintableString UA
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
          UTF8String Київ
    SEQUENCE (2 elem)
      UTCTime 2019-10-22 21:00:00 UTC
      UTCTime 2021-10-22 21:00:00 UTC
    SEQUENCE (6 elem)
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
          UTF8String Мирний Олександр Максимович (Тест)
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.4 surname (X.520 DN component)
          UTF8String Мирний
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.42 givenName (X.520 DN component)
          UTF8String Олександр Максимович (Тест)
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.5 serialNumber (X.520 DN component)
          UTF8String 2468620
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
          PrintableString UA
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
          UTF8String Київ
    SEQUENCE (2 elem)
      SEQUENCE (2 elem)
        OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
        SEQUENCE (2 elem)
          SEQUENCE (5 elem)
            SEQUENCE (2 elem)
              INTEGER 257
              INTEGER 12
            INTEGER 0
            OCTET STRING (33 byte) 10BEE3DB6AEA9E1F86578C45C12594FF942394A7D738F9187E6515017294F4CE01
            INTEGER (256 bit) 5789604461865809771178549250434395392677236560479603245116974155309906…
            OCTET STRING (33 byte) B60FD2D8DCE8A93423C6101BCA91C47A007E6C300B26CD556C9B0E7D20EF292A00
          OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
      BIT STRING (280 bit) 0000010000100001000010111011010100101101100110001101001000110100001000…
        OCTET STRING (33 byte) 0BB52D98D23422830262383BA43EDF9E3C8DA242C3AFF1F6897540AA9676966901
    [3] (1 elem)
      SEQUENCE (12 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.29.14 subjectKeyIdentifier (X.509 extension)
          OCTET STRING (32 byte) A6B1F3FFE570744BF13E4D0F07DA15B086350EC82D3882852DD7249D8AAB6BFC
            OCTET STRING (32 byte) A6B1F3FFE570744BF13E4D0F07DA15B086350EC82D3882852DD7249D8AAB6BFC
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.29.35 authorityKeyIdentifier (X.509 extension)
          OCTET STRING (36 byte) 30228020D8E2D9E7F900307B38F27288B40502C7A7B3FE655290E849C291D064A7338C…
            SEQUENCE (1 elem)
              [0] (32 byte) D8E2D9E7F900307B38F27288B40502C7A7B3FE655290E849C291D064A7338C5C
        SEQUENCE (3 elem)
          OBJECT IDENTIFIER 2.5.29.15 keyUsage (X.509 extension)
          BOOLEAN true
          OCTET STRING (4 byte) 030206C0
            BIT STRING (2 bit) 11
        SEQUENCE (3 elem)
          OBJECT IDENTIFIER 2.5.29.32 certificatePolicies (X.509 extension)
          BOOLEAN true
          OCTET STRING (15 byte) 300D300B06092A8624020101010202
            SEQUENCE (1 elem)
              SEQUENCE (1 elem)
                OBJECT IDENTIFIER 1.2.804.2.1.1.1.2.2
        SEQUENCE (3 elem)
          OBJECT IDENTIFIER 2.5.29.19 basicConstraints (X.509 extension)
          BOOLEAN true
          OCTET STRING (2 byte) 3000
            SEQUENCE (0 elem)
        SEQUENCE (3 elem)
          OBJECT IDENTIFIER 1.3.6.1.5.5.7.1.3 qcStatements (PKIX private extension)
          BOOLEAN true
          OCTET STRING (15 byte) 300D300B06092A8624020101010201
            SEQUENCE (1 elem)
              SEQUENCE (1 elem)
                OBJECT IDENTIFIER 1.2.804.2.1.1.1.2.1
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.29.17 subjectAltName (X.509 extension)
          OCTET STRING (23 byte) 3015A013060A2B060104018237140203A0050C03333834
            SEQUENCE (1 elem)
              [0] (2 elem)
                OBJECT IDENTIFIER 1.3.6.1.4.1.311.20.2.3 universalPrincipalName (Microsoft UPN)
                [0] (1 elem)
                  UTF8String 384
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.29.31 cRLDistributionPoints (X.509 extension)
          OCTET STRING (66 byte) 3040303EA03CA03A8638687474703A2F2F6163736B6964642E676F762E75612F646F77…
            SEQUENCE (1 elem)
              SEQUENCE (1 elem)
                [0] (1 elem)
                  [0] (1 elem)
                    [6] (56 byte) http://acskidd.gov.ua/download/crls/CA-D8E2D9E7-Full.crl
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.29.46 freshestCRL (X.509 extension)
          OCTET STRING (67 byte) 3041303FA03DA03B8639687474703A2F2F6163736B6964642E676F762E75612F646F77…
            SEQUENCE (1 elem)
              SEQUENCE (1 elem)
                [0] (1 elem)
                  [0] (1 elem)
                    [6] (57 byte) http://acskidd.gov.ua/download/crls/CA-D8E2D9E7-Delta.crl
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 1.3.6.1.5.5.7.1.1 authorityInfoAccess (PKIX private extension)
          OCTET STRING (129 byte) 307F303006082B060105050730018624687474703A2F2F6163736B6964642E676F762…
            SEQUENCE (2 elem)
              SEQUENCE (2 elem)
                OBJECT IDENTIFIER 1.3.6.1.5.5.7.48.1 ocsp (PKIX)
                [6] (36 byte) http://acskidd.gov.ua/services/ocsp/
              SEQUENCE (2 elem)
                OBJECT IDENTIFIER 1.3.6.1.5.5.7.48.2 caIssuers (PKIX subject/authority info access descriptor)
                [6] (63 byte) http://acskidd.gov.ua/download/certificates/allacskidd-2019.p7b
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 1.3.6.1.5.5.7.1.11 subjectInfoAccess (PKIX private extension)
          OCTET STRING (51 byte) 3031302F06082B060105050730038623687474703A2F2F6163736B6964642E676F762E…
            SEQUENCE (1 elem)
              SEQUENCE (2 elem)
                OBJECT IDENTIFIER 1.3.6.1.5.5.7.48.3 timeStamping (PKIX subject/authority info access descriptor)
                [6] (35 byte) http://acskidd.gov.ua/services/tsp/
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.29.9 subjectDirectoryAttributes (X.509 extension)
          OCTET STRING (32 byte) 301E301C060C2A8624020101010B01040101310C130A31303130313031303137
            SEQUENCE (1 elem)
              SEQUENCE (2 elem)
                OBJECT IDENTIFIER 1.2.804.2.1.1.1.11.1.4.1.1
                SET (1 elem)
                  PrintableString 1010101017
  SEQUENCE (1 elem)
    OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
  BIT STRING (528 bit) 0000010001000000101010100010011001000010010000010111010010101000010000…
    OCTET STRING (64 byte) AA26424174A8413E8311BEDBA9D37BC15315D0687D083D048B1206863795074E5F344E…
 
 */