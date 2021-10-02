<?php

namespace   PPOLib ;


class PPO
{
    
     /**
     * декодирует  данные   подписаного  сообщения
     * 
     * @param mixed $data
     */
     public static function decrypt($data ){
       
  //  file_put_contents( __DIR__. "/signedanswer",$data) ;
     
          $der =  \ASN1\Type\Constructed\Sequence::fromDER($data) ;   
          $ctype = $der->at(0)->asObjectIdentifier()->oid() ;
             
     
        if($ctype=="1.2.840.113549.1.7.2") {   //signeddata
          $sq =  $der->at(1)->asTagged()->asImplicit(16)->asSequence()  ;
          $sq = $sq->at(0)->asSequence() ;
          $sq2 =  $sq->at(2)->asSequence() ;
          
          $ctype = $sq2->at(0)->asObjectIdentifier()->oid() ; 
          if($ctype=="1.2.840.113549.1.7.1"){   //data 
            $xml =  $sq2->at(1)->asTagged()->asImplicit(16)->asSequence()->at(0)->asOctetString()->string()   ;    
      
            return  $xml ;           
          }
          
          //todo  verify
          
        }   else {
            throw new \Exception("No signed data");
        }
        
        
    }
   
  /**
  * отправка  запроса
  *  
  * @param mixed $data   подписаные  данные
  * @param mixed $type   cmd  или  doc
  */
  public  static  function send($data,$type ){
       
            
            $request = curl_init();

          
             
            curl_setopt_array($request, [
                CURLOPT_URL =>  "http://80.91.165.208:8609/fs/{$type}",
                CURLOPT_POST => true,
                CURLOPT_HEADER => false,
                CURLOPT_HTTPHEADER => array('Content-Type: application/octet-stream', "Content-Length: ".strlen($data)),
                CURLOPT_ENCODING => "",
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_CONNECTTIMEOUT => 20,
                CURLOPT_VERBOSE => 1,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_POSTFIELDS => $data
            ]);

            $return = curl_exec($request);
               
          if(curl_errno($request) > 0)
           {
                
            throw new  \Exception(curl_error($request));
             
           }  
            curl_close($request);            
            
            if(strpos($return,'encoding')>0) { //ответ в  xml
                      return  self::decrypt($return ); 
                        

            }  else {
                return   $return   ;
            }
            
           
        
        
    }
    
   
}
  /*
SEQUENCE (2 elem)
  OBJECT IDENTIFIER 1.2.840.113549.1.7.2 signedData (PKCS #7)
  [0] (1 elem)
    SEQUENCE (5 elem)
      INTEGER 1
      SET (1 elem)
        SEQUENCE (1 elem)
          OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1
      SEQUENCE (2 elem)
        OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
        [0] (1 elem)
          OCTET STRING (1367 byte) 3C3F786D6C2076657273696F6E3D22312E302220656E636F64696E673D2277696E64…
      [0] (1 elem)
        SEQUENCE (3 elem)
          SEQUENCE (8 elem)
            [0] (1 elem)
              INTEGER 2
            INTEGER (159 bit) 507450138549618503925218067946224351162475775488
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
              UTCTime 2020-07-29 21:00:00 UTC
              UTCTime 2022-07-29 21:00:00 UTC
            SEQUENCE (5 elem)
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
                  UTF8String Державна податкова служба України
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
                  UTF8String Фіскальний сервер ПРРО
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.4.5 serialNumber (X.520 DN component)
                  PrintableString 3123956
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
              BIT STRING (280 bit) 0000010000100001011011011110111010011100001001111110011011110010011010…
                OCTET STRING (33 byte) 6DEE9C27E6F26B28770F606823D90DED56AE2D118231F2B7B145BABECC560C2F00
            [3] (1 elem)
              SEQUENCE (13 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.29.14 subjectKeyIdentifier (X.509 extension)
                  OCTET STRING (32 byte) E7D44088D761C38E46064E5770120A55C6D24CC7FC8DC51DBD3E2CDA1C8E49F9
                    OCTET STRING (32 byte) E7D44088D761C38E46064E5770120A55C6D24CC7FC8DC51DBD3E2CDA1C8E49F9
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
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.29.37 extKeyUsage (X.509 extension)
                  OCTET STRING (13 byte) 300B06092A8624020101010309
                    SEQUENCE (1 elem)
                      OBJECT IDENTIFIER 1.2.804.2.1.1.1.3.9
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.29.32 certificatePolicies (X.509 extension)
                  OCTET STRING (15 byte) 300D300B06092A8624020101010202
                    SEQUENCE (1 elem)
                      SEQUENCE (1 elem)
                        OBJECT IDENTIFIER 1.2.804.2.1.1.1.2.2
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.29.19 basicConstraints (X.509 extension)
                  OCTET STRING (2 byte) 3000
                    SEQUENCE (0 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 1.3.6.1.5.5.7.1.3 qcStatements (PKIX private extension)
                  OCTET STRING (15 byte) 300D300B06092A8624020101010201
                    SEQUENCE (1 elem)
                      SEQUENCE (1 elem)
                        OBJECT IDENTIFIER 1.2.804.2.1.1.1.2.1
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 2.5.29.17 subjectAltName (X.509 extension)
                  OCTET STRING (23 byte) 3015A013060A2B060104018237140203A0050C03343037
                    SEQUENCE (1 elem)
                      [0] (2 elem)
                        OBJECT IDENTIFIER 1.3.6.1.4.1.311.20.2.3 universalPrincipalName (Microsoft UPN)
                        [0] (1 elem)
                          UTF8String 407
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
                  OCTET STRING (50 byte) 3030301A060C2A8624020101010B01040201310A130834333030353339333012060C2A…
                    SEQUENCE (2 elem)
                      SEQUENCE (2 elem)
                        OBJECT IDENTIFIER 1.2.804.2.1.1.1.11.1.4.2.1
                        SET (1 elem)
                          PrintableString 43005393
                      SEQUENCE (2 elem)
                        OBJECT IDENTIFIER 1.2.804.2.1.1.1.11.1.4.1.1
                        SET (1 elem)
                          PrintableString
          SEQUENCE (1 elem)
            OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
          BIT STRING (528 bit) 0000010001000000101100010010000010110001101101010111000110011101100100…
            OCTET STRING (64 byte) B120B1B5719D90BE01858A7B8CB7B40C632B3C3473DAA77366EA50E3B2D74160D52E15…
      SET (1 elem)
        SEQUENCE (7 elem)
          INTEGER 1
          [0] (1 elem)
            OCTET STRING (32 byte) E7D44088D761C38E46064E5770120A55C6D24CC7FC8DC51DBD3E2CDA1C8E49F9
          SEQUENCE (1 elem)
            OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1
          [0] (4 elem)
            SEQUENCE (2 elem)
              OBJECT IDENTIFIER 1.2.840.113549.1.9.4 messageDigest (PKCS #9)
              SET (1 elem)
                OCTET STRING (32 byte) BF5E08F210BDE80B1FF5B885CB50C83C2B1D02BF9A81FCAE6DD861DA180C7942
            SEQUENCE (2 elem)
              OBJECT IDENTIFIER 1.2.840.113549.1.9.3 contentType (PKCS #9)
              SET (1 elem)
                OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
            SEQUENCE (2 elem)
              OBJECT IDENTIFIER 1.2.840.113549.1.9.16.2.47 signingCertificateV2 (S/MIME Authenticated Attributes)
              SET (1 elem)
                SEQUENCE (1 elem)
                  SEQUENCE (1 elem)
                    SEQUENCE (3 elem)
                      SEQUENCE (1 elem)
                        OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1
                      OCTET STRING (32 byte) 9DB1C1153A91DFEAC6BD4C863A7B79703AD67E3DDE435810D3A94E7BB4350E33
                      SEQUENCE (2 elem)
                        SEQUENCE (1 elem)
                          [4] (1 elem)
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
                        INTEGER (159 bit) 507450138549618503925218067946224351162475775488
            SEQUENCE (2 elem)
              OBJECT IDENTIFIER 1.2.840.113549.1.9.5 signingTime (PKCS #9)
              SET (1 elem)
                UTCTime 2020-11-26 15:54:47 UTC
          SEQUENCE (1 elem)
            OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
          OCTET STRING (64 byte) E15B02048A38C07A4824E44E20E33FA74FC6893211623628957F8887622FC11BDDA758…
          [1] (1 elem)
            SEQUENCE (2 elem)
              OBJECT IDENTIFIER 1.2.840.113549.1.9.16.2.14 timeStampToken (S/MIME Authenticated Attributes)
              SET (1 elem)
                SEQUENCE (2 elem)
                  OBJECT IDENTIFIER 1.2.840.113549.1.7.2 signedData (PKCS #7)
                  [0] (1 elem)
                    SEQUENCE (5 elem)
                      INTEGER 3
                      SET (1 elem)
                        SEQUENCE (1 elem)
                          OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1
                      SEQUENCE (2 elem)
                        OBJECT IDENTIFIER 1.2.840.113549.1.9.16.1.4 tSTInfo (S/MIME Content Types)
                        [0] (1 elem)
                          OCTET STRING (90 byte) 3058020101060A2A8624020101010203013030300C060A2A8624020101010102010420…
                            SEQUENCE (5 elem)
                              INTEGER 1
                              OBJECT IDENTIFIER 1.2.804.2.1.1.1.2.3.1
                              SEQUENCE (2 elem)
                                SEQUENCE (1 elem)
                                  OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1
                                OCTET STRING (32 byte) 45DB12B86D0A894544012DB0709795603E52B3C63DE593A74463521704D6F2A1
                              INTEGER 260575656
                              GeneralizedTime 2020-11-26 13:54:59 UTC
                      [0] (1 elem)
                        SEQUENCE (3 elem)
                          SEQUENCE (8 elem)
                            [0] (1 elem)
                              INTEGER 2
                            INTEGER (158 bit) 352334916528167280788249162252414465964781862912
                            SEQUENCE (1 elem)
                              OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
                            SEQUENCE (6 elem)
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
                                  UTF8String Міністерство юстиції України
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
                                  UTF8String Адміністратор ІТС ЦЗО
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
                                  UTF8String Центральний засвідчувальний орган
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.5 serialNumber (X.520 DN component)
                                  UTF8String UA-00015622-2017
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
                                  PrintableString UA
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
                                  UTF8String Київ
                            SEQUENCE (2 elem)
                              UTCTime 2019-09-24 14:25:00 UTC
                              UTCTime 2024-09-24 14:25:00 UTC
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
                                  UTF8String TSP-сервер КНЕДП - ІДД ДПС
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
                              BIT STRING (280 bit) 0000010000100001101001101011111101101110010101011110001111000110110100…
                                OCTET STRING (33 byte) A6BF6E55E3C6D00EA36E424CB25727566C17F311A79556FA0A4EF9E61D7160ED01
                            [3] (1 elem)
                              SEQUENCE (11 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.29.14 subjectKeyIdentifier (X.509 extension)
                                  OCTET STRING (32 byte) 21A4A1ECF187A9B5D02B9C4F3F25511BE6AE1198D2EFC206A47FFC74965AB986
                                    OCTET STRING (32 byte) 21A4A1ECF187A9B5D02B9C4F3F25511BE6AE1198D2EFC206A47FFC74965AB986
                                SEQUENCE (3 elem)
                                  OBJECT IDENTIFIER 2.5.29.15 keyUsage (X.509 extension)
                                  BOOLEAN true
                                  OCTET STRING (4 byte) 030206C0
                                    BIT STRING (2 bit) 11
                                SEQUENCE (3 elem)
                                  OBJECT IDENTIFIER 2.5.29.37 extKeyUsage (X.509 extension)
                                  BOOLEAN true
                                  OCTET STRING (26 byte) 301806082B06010505070308060C2B060104018197460101081F
                                    SEQUENCE (2 elem)
                                      OBJECT IDENTIFIER 1.3.6.1.5.5.7.3.8 timeStamping (PKIX key purpose)
                                      OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.8.31
                                SEQUENCE (3 elem)
                                  OBJECT IDENTIFIER 2.5.29.32 certificatePolicies (X.509 extension)
                                  BOOLEAN true
                                  OCTET STRING (15 byte) 300D300B06092A8624020101010202
                                    SEQUENCE (1 elem)
                                      SEQUENCE (1 elem)
                                        OBJECT IDENTIFIER 1.2.804.2.1.1.1.2.2
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.29.17 subjectAltName (X.509 extension)
                                  OCTET STRING (166 byte) 3081A3A056060C2B0601040181974601010402A0460C4430343035332C20D0BC2E20D…
                                    SEQUENCE (4 elem)
                                      [0] (2 elem)
                                        OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.4.2
                                        [0] (1 elem)
                                          UTF8String 04053, м. Київ, Львівська площа, будинок 8
                                      [0] (2 elem)
                                        OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.4.1
                                        [0] (1 elem)
                                          UTF8String +38(044) 2840010
                                      [2] (14 byte) acskidd.gov.ua
                                      [1] (21 byte) inform@acskidd.gov.ua
                                SEQUENCE (3 elem)
                                  OBJECT IDENTIFIER 2.5.29.19 basicConstraints (X.509 extension)
                                  BOOLEAN true
                                  OCTET STRING (2 byte) 3000
                                    SEQUENCE (0 elem)
                                SEQUENCE (3 elem)
                                  OBJECT IDENTIFIER 1.3.6.1.5.5.7.1.3 qcStatements (PKIX private extension)
                                  BOOLEAN true
                                  OCTET STRING (25 byte) 3017300B06092A86240201010102013008060604008E460104
                                    SEQUENCE (2 elem)
                                      SEQUENCE (1 elem)
                                        OBJECT IDENTIFIER 1.2.804.2.1.1.1.2.1
                                      SEQUENCE (1 elem)
                                        OBJECT IDENTIFIER 0.4.0.1862.1.4 etsiQcsQcSSCD (ETSI TS 101 862 qualified certificates)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.29.35 authorityKeyIdentifier (X.509 extension)
                                  OCTET STRING (36 byte) 30228020BDB73E7BF0D575B24802783D9E05A9509776C175F7AC8176740807967A3420…
                                    SEQUENCE (1 elem)
                                      [0] (32 byte) BDB73E7BF0D575B24802783D9E05A9509776C175F7AC8176740807967A342014
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.29.31 cRLDistributionPoints (X.509 extension)
                                  OCTET STRING (59 byte) 30393037A035A0338631687474703A2F2F637A6F2E676F762E75612F646F776E6C6F61…
                                    SEQUENCE (1 elem)
                                      SEQUENCE (1 elem)
                                        [0] (1 elem)
                                          [0] (1 elem)
                                            [6] (49 byte) http://czo.gov.ua/download/crls/CZO-2017-Full.crl
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.29.46 freshestCRL (X.509 extension)
                                  OCTET STRING (60 byte) 303A3038A036A0348632687474703A2F2F637A6F2E676F762E75612F646F776E6C6F61…
                                    SEQUENCE (1 elem)
                                      SEQUENCE (1 elem)
                                        [0] (1 elem)
                                          [0] (1 elem)
                                            [6] (50 byte) http://czo.gov.ua/download/crls/CZO-2017-Delta.crl
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 1.3.6.1.5.5.7.1.1 authorityInfoAccess (PKIX private extension)
                                  OCTET STRING (48 byte) 302E302C06082B060105050730018620687474703A2F2F637A6F2E676F762E75612F73…
                                    SEQUENCE (1 elem)
                                      SEQUENCE (2 elem)
                                        OBJECT IDENTIFIER 1.3.6.1.5.5.7.48.1 ocsp (PKIX)
                                        [6] (32 byte) http://czo.gov.ua/services/ocsp/
                          SEQUENCE (1 elem)
                            OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
                          BIT STRING (880 bit) 0000010001101100000001110100011010011110010010010010111001011110101010…
                            OCTET STRING (108 byte) 07469E492E5EABFC794127713165484D7180DB00B12E0B9E9638F7A2115B8F0119DE1…
                      SET (1 elem)
                        SEQUENCE (6 elem)
                          INTEGER 1
                          SEQUENCE (2 elem)
                            SEQUENCE (6 elem)
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
                                  UTF8String Міністерство юстиції України
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
                                  UTF8String Адміністратор ІТС ЦЗО
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
                                  UTF8String Центральний засвідчувальний орган
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.5 serialNumber (X.520 DN component)
                                  UTF8String UA-00015622-2017
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
                                  PrintableString UA
                              SET (1 elem)
                                SEQUENCE (2 elem)
                                  OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
                                  UTF8String Київ
                            INTEGER (158 bit) 352334916528167280788249162252414465964781862912
                          SEQUENCE (1 elem)
                            OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1
                          [0] (4 elem)
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.840.113549.1.9.3 contentType (PKCS #9)
                              SET (1 elem)
                                OBJECT IDENTIFIER 1.2.840.113549.1.9.16.1.4 tSTInfo (S/MIME Content Types)
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.840.113549.1.9.5 signingTime (PKCS #9)
                              SET (1 elem)
                                UTCTime 2020-11-26 13:54:59 UTC
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.840.113549.1.9.4 messageDigest (PKCS #9)
                              SET (1 elem)
                                OCTET STRING (32 byte) 00F83927A3C53B3D98252873AB893F565868A94E988045A9D6A8853F743A115E
                            SEQUENCE (2 elem)
                              OBJECT IDENTIFIER 1.2.840.113549.1.9.16.2.47 signingCertificateV2 (S/MIME Authenticated Attributes)
                              SET (1 elem)
                                SEQUENCE (1 elem)
                                  SEQUENCE (1 elem)
                                    SEQUENCE (3 elem)
                                      SEQUENCE (1 elem)
                                        OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1
                                      OCTET STRING (32 byte) AF164CD86701E5D906EA27A1449CAE83EF168D61E2EA479407D96F65A52CE13D
                                      SEQUENCE (2 elem)
                                        SEQUENCE (1 elem)
                                          [4] (1 elem)
                                            SEQUENCE (6 elem)
                                              SET (1 elem)
                                                SEQUENCE (2 elem)
                                                  OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
                                                  UTF8String Міністерство юстиції України
                                              SET (1 elem)
                                                SEQUENCE (2 elem)
                                                  OBJECT IDENTIFIER 2.5.4.11 organizationalUnitName (X.520 DN component)
                                                  UTF8String Адміністратор ІТС ЦЗО
                                              SET (1 elem)
                                                SEQUENCE (2 elem)
                                                  OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
                                                  UTF8String Центральний засвідчувальний орган
                                              SET (1 elem)
                                                SEQUENCE (2 elem)
                                                  OBJECT IDENTIFIER 2.5.4.5 serialNumber (X.520 DN component)
                                                  UTF8String UA-00015622-2017
                                              SET (1 elem)
                                                SEQUENCE (2 elem)
                                                  OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
                                                  PrintableString UA
                                              SET (1 elem)
                                                SEQUENCE (2 elem)
                                                  OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
                                                  UTF8String Київ
                                        INTEGER (158 bit) 352334916528167280788249162252414465964781862912
                          SEQUENCE (1 elem)
                            OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
                          OCTET STRING (64 byte) 8094512D1528DE1C7CB7A96B691FAA4ED038A29128EBE7D652D18E6CAAE28D572A1867…
                          */