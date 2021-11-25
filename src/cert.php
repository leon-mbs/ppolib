<?php

namespace PPOLib;

use \PPOLib\Util;
use  \Sop\ASN1\Type\Constructed\Sequence;
use  \Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;

class Cert
{

    private $_publickey;
    private $_raw;
    

    /**
    * загрузка  сертификата
    * 
    * @param mixed $cert данные файла  сертификата
    * @return Cert
    */
    public static function load($cert) {

        $c = new Cert();
        $c->_raw = $cert;
        $seq =  Sequence::fromDER($cert);
        $seq = $seq->at(0)->asSequence();

        $serial = $seq->at(1)
                ->asInteger()
                ->number();
      
   
       
        $algo = $seq->at(2)->asSequence()->at(0)->asObjectIdentifier()->oid();
        $pki = $seq->at(6)->asSequence();

        $algo = $pki->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid();
        $curveparam = $pki->at(0)->asSequence()->at(1)->asSequence()->at(0)->asSequence();
        $curve = new Curve($curveparam, true);

        $pkey = $pki->at(1)->asBitString()->string();
        $a = Util::bstr2array($pkey);
        $a = array_slice($a, 2);
        $a = array_reverse($a);

        $p = Field::fromString(Util::array2hex($a), 16, $curve);

        $c->_publickey = $curve->expand($p);
      //   $x=$c->_publickey->x->toString(16);
      //   $y=$c->_publickey->y->toString(16);
        return $c;
    }
    //публичный ключ
    public function pub() {

        $pub = new Pub($this->_publickey);
        return $pub;
    }

    public function getAsn1() {

        return  Sequence::fromDER($this->_raw);
    }

    public function getHash() {
        $hash = \PPOLib\Algo\Hash::gosthash($this->_raw);

        return $hash;
    }
    public function getOwner()   {
         $seq =  Sequence::fromDER($this->_raw);
         $seq = $seq->at(0)->asSequence();

        $cert_issuer = $seq->at(5)->asSequence();
        foreach($cert_issuer as $c) {
           $set = $c->asSet()  ;
           $id = $set->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid() ;
           if($id=="2.5.4.3"){    // 2.5.4.10
               $owner = $set->at(0)->asSequence()->at(1)->asUTF8String()->string();
               break;
           }
        }    

        return $owner;
    }

}
   /*
   SEQUENCE (3 elem)
  SEQUENCE (8 elem)
    [0] (1 elem)
      INTEGER 2
    INTEGER (159 bit) 507450138549618503925218067946368455357335504896
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
      UTCTime 2020-09-30 21:00:00 UTC
      UTCTime 2022-09-30 20:59:59 UTC
    SEQUENCE (8 elem)
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.10 organizationName (X.520 DN component)
          UTF8String Тестовий платник 3 (Тестовий сертифікат)
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
          UTF8String Сидоренко Василь Леонідович (Тест)
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.4 surname (X.520 DN component)
          UTF8String Сидоренко
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.42 givenName (X.520 DN component)
          UTF8String Василь Леонідович (Тест)
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.5 serialNumber (X.520 DN component)
          PrintableString 2468598
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
          PrintableString UA
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
          UTF8String Жашків
      SET (1 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.4.8 stateOrProvinceName (X.520 DN component)
          UTF8String Черкаська
    SEQUENCE (2 elem)
      SEQUENCE (2 elem)
        OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
        SEQUENCE (2 elem)
          SEQUENCE (5 elem)
            SEQUENCE (2 elem)
              INTEGER 431
              SEQUENCE (3 elem)
                INTEGER 1
                INTEGER 3
                INTEGER 5
            INTEGER 1
            OCTET STRING (54 byte) F3CA40C669A4DA173149CA12C32DAE186B53AC6BC6365997DEAEAE8AD2D888F9BFD534…
            INTEGER (430 bit) 2772669694120814859578414184143083703436437075375816575170479580585904…
            OCTET STRING (54 byte) 7C857C94C5433BFD991E17C22684065850A9A249ED7BC249AE5A4E878689F872EF7AD5…
          OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
      BIT STRING (448 bit) 0000010000110110100100001010100001110111011001000101110011001011111000…
        OCTET STRING (54 byte) 90A877645CCBE19F6C3959E6CC06CA9C088F8E135623ACB797ADB40A7A42F6FC0960AE…
    [3] (1 elem)
      SEQUENCE (12 elem)
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.29.14 subjectKeyIdentifier (X.509 extension)
          OCTET STRING (34 byte) 04202F5EE8C33BA5912AAEBDCEA1E00402F0AF18E502D4BA72FD501B20E8CEE4FDDF
            OCTET STRING (32 byte) 2F5EE8C33BA5912AAEBDCEA1E00402F0AF18E502D4BA72FD501B20E8CEE4FDDF
        SEQUENCE (2 elem)
          OBJECT IDENTIFIER 2.5.29.35 authorityKeyIdentifier (X.509 extension)
          OCTET STRING (36 byte) 30228020D8E2D9E7F900307B38F27288B40502C7A7B3FE655290E849C291D064A7338C…
            SEQUENCE (1 elem)
              [0] (32 byte) D8E2D9E7F900307B38F27288B40502C7A7B3FE655290E849C291D064A7338C5C
        SEQUENCE (3 elem)
          OBJECT IDENTIFIER 2.5.29.15 keyUsage (X.509 extension)
          BOOLEAN true
          OCTET STRING (4 byte) 03020308
            BIT STRING (5 bit) 00001
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
          OCTET STRING (23 byte) 3015A013060A2B060104018237140203A0050C03343135
            SEQUENCE (1 elem)
              [0] (2 elem)
                OBJECT IDENTIFIER 1.3.6.1.4.1.311.20.2.3 universalPrincipalName (Microsoft UPN)
                [0] (1 elem)
                  UTF8String 415
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
          OCTET STRING (60 byte) 303A301A060C2A8624020101010B01040201310A13083334353534333632301C060C2A…
            SEQUENCE (2 elem)
              SEQUENCE (2 elem)
                OBJECT IDENTIFIER 1.2.804.2.1.1.1.11.1.4.2.1
                SET (1 elem)
                  PrintableString 34554362
              SEQUENCE (2 elem)
                OBJECT IDENTIFIER 1.2.804.2.1.1.1.11.1.4.1.1
                SET (1 elem)
                  PrintableString 1010101014
  SEQUENCE (1 elem)
    OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
  BIT STRING (528 bit) 0000010001000000011001010000000111101110111010100001001011001001100001…
    OCTET STRING (64 byte) 6501EEEA12C98640C3FD518A5BA93AF9EA963CCB7C9D6313C7C2811348F04E5BC85DDC…
   */
 