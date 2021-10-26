<?php

namespace PPOLib;

use \ASN1\Type\Constructed\Sequence;
use \ASN1\Type\Tagged\ImplicitlyTaggedType;
use \ASN1\Type\Primitive\OctetString;
use \ASN1\Type\Primitive\ObjectIdentifier;
use \ASN1\Type\Constructed\Set;
use \ASN1\Type\Primitive\Integer;
use \ASN1\Type\Primitive\UTCTime;


class PPO
{

    public static function sign($message, Priv $key, Cert $cert) {

        $hash = \PPOLib\Algo\Hash::gosthash($message);
        $hash = Util::array2bstr($hash);
        $certhash = $cert->getHash();
        $certhash = Util::array2bstr($certhash);

        $cert = $cert->getAsn1();


        $dataos = new OctetString($message);
        $data = new Sequence($dataos);
        $data = new ImplicitlyTaggedType(0, $data);
        $dataid = new ObjectIdentifier("1.2.840.113549.1.7.1");   //данные

        $data = new Sequence($dataid, $data);

        $algoid = new ObjectIdentifier("1.2.804.2.1.1.1.1.2.1");    //Gost34311


        $version = new Integer(1);
        $algoidenc = new ObjectIdentifier("1.2.804.2.1.1.1.1.3.1.1");    //DSTU_4145_LE


        $cer = $cert->at(0)->asSequence();

        $cert_serial = $cer->at(1)->asInteger();;
        $cert_issuer = $cer->at(3)->asSequence();

        $cert_issuer4 = new Sequence(new ImplicitlyTaggedType(4, new Sequence($cert_issuer)));
        $cv2 = new Sequence($cert_issuer4, $cert_serial);

        //атрибуты для  подписи

        $seq3 = new Sequence(new Sequence(new ObjectIdentifier("1.2.804.2.1.1.1.1.2.1")), new OctetString($certhash), $cv2);

        $attr1 = new Sequence(new ObjectIdentifier("1.2.840.113549.1.9.16.2.47"), new Set(new Sequence(new Sequence($seq3))));
        $attr2 = new Sequence(new ObjectIdentifier("1.2.840.113549.1.9.3"), new Set(new ObjectIdentifier("1.2.840.113549.1.7.1")));
        $attr3 = new Sequence(new ObjectIdentifier("1.2.840.113549.1.9.4"), new Set(new OctetString($hash)));
        $attr4 = new Sequence(new ObjectIdentifier("1.2.840.113549.1.9.5"), new Set(new UTCTime(new \DateTimeImmutable('1970-01-01 00:00:00 UTC'))));


        $attrs = new ImplicitlyTaggedType(0, new Sequence($attr1, $attr2, $attr3, $attr4));


        $derattrs = (new Set($attr1, $attr2, $attr3, $attr4))->toDER();

        $ahash = \PPOLib\Algo\Hash::gosthash($derattrs);
        $ahash = Util::array2bstr($ahash);

        $sign = $key->sign($ahash);


        //  $sign = "0E469C8C9019155210E3F0C0C7D1807486598D1CED1A5851C3EA494A55DBDA54ADA02C…"; //подпись

        $sign = new OctetString($sign);
        $signerinfo = new Sequence($version, new Sequence($cert_issuer, $cert_serial), new Sequence($algoid), $attrs, new Sequence($algoidenc), $sign);


        $signerinfo = new Set($signerinfo);
        $signeddata = new Sequence($version, new Set(new Sequence($algoid)), $data, new ImplicitlyTaggedType(0, new Sequence($cert)), $signerinfo);

        $signeddata = new Sequence($signeddata);
        $signeddata = new ImplicitlyTaggedType(0, $signeddata);


        $signeddataid = new ObjectIdentifier("1.2.840.113549.1.7.2");    //signedData
        $result = new  Sequence($signeddataid, $signeddata);
        return $result->toDER();
    }

    public static function decrypt($message, $onlydata = false) {

        $der = Sequence::fromDER($message);
        $ctype = $der->at(0)->asObjectIdentifier()->oid();

        if ($ctype != "1.2.840.113549.1.7.2") {
            return;
        }   //signeddata

        $sq5 = $der->at(1)->asTagged()->asImplicit(16)->asSequence();
        $sq5 = $sq5->at(0)->asSequence();

        //1.2.804.2.1.1.1.1.2.1
        $algo = $sq5->at(1)->asSet();
        $algo = $algo->at(0)->asSequence();
        //Gost34311
        $algo = $algo->at(0)->asObjectIdentifier()->oid();

        //data
        $sqdata = $sq5->at(2)->asSequence();

        $ctype = $sqdata->at(0)->asObjectIdentifier()->oid();
        if ($ctype == "1.2.840.113549.1.7.1") {   //data
            $sqxml = $sqdata->at(1)->asTagged()->asImplicit(16)->asSequence();
            $xml = $sqxml->at(0)->asOctetString()->string();
            if ($onlydata) {
                return $xml;
            }
        }

        //cert
        $sqcert = $sq5->at(3)->asTagged()->asImplicit(16)->asSequence();
        $dercert = $sqcert->at(0)->asSequence()->toDer();

        $cert = \PPOLib\Cert::load($dercert);

        //  $tbscert = $sqcert->at(0)->asSequence()  ;


        //info
        $signerinfo1 = $sq5->at(4)->asSet();
        $signerinfo = $signerinfo1->at(0)->asSequence();

        $v = $signerinfo->at(0)->asInteger()->number();

        // $ci = $signerinfo->at(1)->asSequence() ;
        //
        // $cidata=      $ci->at(0)->asSequence() ;

        // $sn=  $ci->at(1)->asInteger()->number(); ;

        //Gost34311        1 2 804 2 1 1 1 1 2 1"
        //  $cda = $signerinfo->at(2)->asSequence()->at(0)->asObjectIdentifier()->oid();

        //attr
        $a = $signerinfo->at(3)->asTagged()->asImplicit(16)->asSequence();

        $c = count($a);

        $derattrs = (new Set($a->at(0)->asSequence(), $a->at(1)->asSequence(), $a->at(2)->asSequence(), $a->at(3)->asSequence()))->toDER();

        $ahash = \PPOLib\Algo\Hash::gosthash($derattrs);
        $ahash = Util::array2bstr($ahash);


        $signature = $signerinfo->at(5)->asOctetString()->string();


        $b = $cert->pub()->verify($ahash, $signature);


        if ($b) {
            return $xml;
        } else {
            return "";
        }

    }


    /**
     * отправка  запроса
     *
     * @param mixed $data подписаные  данные
     * @param mixed $type cmd  или  doc
     */
    public static function send($data, $type) {


        $request = curl_init();


        curl_setopt_array($request, [
            CURLOPT_URL            => "http://80.91.165.208:8609/fs/{$type}",
            CURLOPT_POST           => true,
            CURLOPT_HEADER         => false,
            CURLOPT_HTTPHEADER     => array('Content-Type: application/octet-stream', "Content-Length: " . strlen($data)),
            CURLOPT_ENCODING       => "",
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 20,
            CURLOPT_VERBOSE        => 1,
            CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
            CURLOPT_POSTFIELDS     => $data
        ]);

        $return = curl_exec($request);

        if (curl_errno($request) > 0) {

            throw new  \Exception(curl_error($request));

        }
        curl_close($request);

        if (strpos($return, 'encoding') > 0) { //ответ в  xml
            return self::decrypt($return);


        } else {
            return $return;
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
         OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1    Gost34311

     SEQUENCE (2 elem)
       OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
       [0] (1 elem)
         OCTET STRING (21 byte) {"Command":"Objects"}

     [0] (1 elem)
       SEQUENCE (3 elem)
         SEQUENCE (8 elem)
           [0] (1 elem)
             INTEGER 2
           INTEGER (159 bit) 507450138549618503925218067945108024704584685824
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
             UTCTime 2021-09-28 11:16:35 UTC
             UTCTime 2023-09-28 11:16:35 UTC
           SEQUENCE (5 elem)
             SET (1 elem)
               SEQUENCE (2 elem)
                 OBJECT IDENTIFIER 2.5.4.3 commonName (X.520 DN component)
                 UTF8String Гриньова О.О. для РРО № 1
             SET (1 elem)
               SEQUENCE (2 elem)
                 OBJECT IDENTIFIER 2.5.4.5 serialNumber (X.520 DN component)
                 PrintableString TINUA-2108114448
             SET (1 elem)
               SEQUENCE (2 elem)
                 OBJECT IDENTIFIER 2.5.4.6 countryName (X.520 DN component)
                 PrintableString UA
             SET (1 elem)
               SEQUENCE (2 elem)
                 OBJECT IDENTIFIER 2.5.4.7 localityName (X.520 DN component)
                 UTF8String Красний Луч
             SET (1 elem)
               SEQUENCE (2 elem)
                 OBJECT IDENTIFIER 2.5.4.8 stateOrProvinceName (X.520 DN component)
                 UTF8String Луганська
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
             BIT STRING (280 bit) 0000010000100001001011110101001000001001101110011101001110110111111000…
               OCTET STRING (33 byte) 2F5209B9D3B7E11CD9AFE566F7B42480A279086CC6B02255D6807D1EE3253D3D01
           [3] (1 elem)
             SEQUENCE (13 elem)
               SEQUENCE (2 elem)
                 OBJECT IDENTIFIER 2.5.29.14 subjectKeyIdentifier (X.509 extension)
                 OCTET STRING (34 byte) 0420E1B13ED5B3BD75DE937920589BF2C21EB6C3BC45082079C43469905B0D81780D
                   OCTET STRING (32 byte) E1B13ED5B3BD75DE937920589BF2C21EB6C3BC45082079C43469905B0D81780D
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
                 OCTET STRING (63 byte) 303D303B06092A8624020101010202302E302C06082B06010505070201162068747470…
                   SEQUENCE (1 elem)
                     SEQUENCE (2 elem)
                       OBJECT IDENTIFIER 1 2 804 2 1 1 1 2 2
                       SEQUENCE (1 elem)
                         SEQUENCE (2 elem)
                           OBJECT IDENTIFIER 1.3.6.1.5.5.7.2.1 cps (PKIX policy qualifier)
                           IA5String https://acskidd.gov.ua/reglament
               SEQUENCE (2 elem)
                 OBJECT IDENTIFIER 2.5.29.19 basicConstraints (X.509 extension)
                 OCTET STRING (2 byte) 3000
                   SEQUENCE (0 elem)
               SEQUENCE (2 elem)
                 OBJECT IDENTIFIER 1.3.6.1.5.5.7.1.3 qcStatements (PKIX private extension)
                 OCTET STRING (96 byte) 305E3008060604008E460101302E060604008E46010530243022161C68747470733A2F…
                   SEQUENCE (4 elem)
                     SEQUENCE (1 elem)
                       OBJECT IDENTIFIER 0.4.0.1862.1.1 etsiQcsCompliance (ETSI TS 101 862 qualified certificates)
                     SEQUENCE (2 elem)
                       OBJECT IDENTIFIER 0.4.0.1862.1.5
                       SEQUENCE (1 elem)
                         SEQUENCE (2 elem)
                           IA5String https://acskidd.gov.ua/about
                           PrintableString en
                     SEQUENCE (2 elem)
                       OBJECT IDENTIFIER 1.3.6.1.5.5.7.11.2 pkixQCSyntax-v2 (PKIX qualified certificates)
                       SEQUENCE (1 elem)
                         OBJECT IDENTIFIER 0.4.0.194121.1.1
                     SEQUENCE (1 elem)
                       OBJECT IDENTIFIER 1 2 804 2 1 1 1 2 1
               SEQUENCE (2 elem)
                 OBJECT IDENTIFIER 2.5.29.17 subjectAltName (X.509 extension)
                 OCTET STRING (23 byte) 3015A013060A2B060104018237140203A0050C03393939
                   SEQUENCE (1 elem)
                     [0] (2 elem)
                       OBJECT IDENTIFIER 1.3.6.1.4.1.311.20.2.3 universalPrincipalName (Microsoft UPN)
                       [0] (1 elem)
                         UTF8String 999
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
                 OCTET STRING (32 byte) 301E301C060C2A8624020101010B01040101310C130A32313038313134343438
                   SEQUENCE (1 elem)
                     SEQUENCE (2 elem)
                       OBJECT IDENTIFIER 1 2 804 2 1 1 1 11 1 4 1 1   DRFO
                       SET (1 elem)
                         PrintableString 2108114448
         SEQUENCE (1 elem)
           OBJECT IDENTIFIER 1 2 804 2 1 1 1 1 3 1 1    DSTU_4145_LE
         BIT STRING (528 bit) 0000010001000000010000100100001110111100011101110100000000000010010001…
           OCTET STRING (64 byte) 4243BC7740024697E95B7C1393F96F5B90B968CEAD11BAE9CB69DF3714E80905087E6F…


     //signer info
     SET (1 elem)
       SEQUENCE (6 elem)
         INTEGER 1

         SEQUENCE (2 elem)
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

           INTEGER (159 bit) 507450138549618503925218067945108024704584685824

         //digestAlgorithm
         SEQUENCE (1 elem)
           OBJECT IDENTIFIER 1 2 804 2 1 1 1 1 2 1       Gost34311

         [0] (4 elem)
           SEQUENCE (2 elem)
             OBJECT IDENTIFIER 1.2.840.113549.1.9.16.2.47 signingCertificateV2 (S/MIME Authenticated Attributes)
             SET (1 elem)
               SEQUENCE (1 elem)
                 SEQUENCE (1 elem)
                   SEQUENCE (3 elem)
                     SEQUENCE (1 elem)
                       OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.2.1   Gost34311
                     OCTET STRING (32 byte) 595B51F2F340DAABCF014F2D22C7792A300A9AC26963C46CE4FECC2EF43B990E
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
                       INTEGER (159 bit) 507450138549618503925218067945108024704584685824
           SEQUENCE (2 elem)
             OBJECT IDENTIFIER 1.2.840.113549.1.9.3 contentType (PKCS #9)
             SET (1 elem)
               OBJECT IDENTIFIER 1.2.840.113549.1.7.1 data (PKCS #7)
           SEQUENCE (2 elem)
             OBJECT IDENTIFIER 1.2.840.113549.1.9.4 messageDigest (PKCS #9)
             SET (1 elem)
               OCTET STRING (32 byte) F19E708EB39CD0C391685D0D2E749053AE3DC41FFBA22E5B0EC2631A27A0044E
           SEQUENCE (2 elem)
             OBJECT IDENTIFIER 1.2.840.113549.1.9.5 signingTime (PKCS #9)
             SET (1 elem)
               UTCTime 1970-01-01 00:00:00 UTC

         SEQUENCE (1 elem)
           OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1      DSTU_4145_LE

         OCTET STRING (64 byte) 0E469C8C9019155210E3F0C0C7D1807486598D1CED1A5851C3EA494A55DBDA54ADA02C…

*/