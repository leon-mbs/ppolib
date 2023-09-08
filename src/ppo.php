<?php

namespace PPOLib;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Constructed\Set;
use Sop\ASN1\Type\Primitive\Integer;
use Sop\ASN1\Type\Primitive\UTCTime;

/**
 * основной класс  библиотеки
 */
class PPO
{
    /**
     * Подписывает и упаковывает  документ  или  команду  для  отправки
     *
     * @param mixed $message   данные
     * @param Priv $key   приватный ключ
     * @param $cert  сертификат
     * @return string   подписаное  сообщение
     */
    public static function sign($message, Priv $key, Cert $cert) {


        $hashid="1.2.804.2.1.1.1.1.2.1";  //gost89


        $hash = \PPOLib\Algo\Hash::gosthash($message);


        //   $hashid="1.2.804.2.1.1.1.1.2.2";    //dstu7564

        //   $hash = \PPOLib\Algo\DSTU7564::hash($message);



        $hash = Util::array2bstr($hash);
        $certhash = $cert->getHash();
        $certhash = Util::array2bstr($certhash);

        $cert = $cert->getAsn1();

        $dataos = new OctetString($message);
        $data = new Sequence($dataos);
        $data = new ImplicitlyTaggedType(0, $data);
        $dataid = new ObjectIdentifier("1.2.840.113549.1.7.1");   //данные

        $data = new Sequence($dataid, $data);

        $algoid = new ObjectIdentifier($hashid);    //hashid


        $version = new Integer(1);
        $algoidenc = new ObjectIdentifier("1.2.804.2.1.1.1.1.3.1.1");    //DSTU_4145_LE


        $cer = $cert->at(0)->asSequence();

        $cert_serial = $cer->at(1)->asInteger();
        ;
        $cert_issuer = $cer->at(3)->asSequence();

        $cert_issuer4 = new Sequence(new ImplicitlyTaggedType(4, new Sequence($cert_issuer)));
        $cv2 = new Sequence($cert_issuer4, $cert_serial);

        //атрибуты для  подписи

        $seq3 = new Sequence(new Sequence(new ObjectIdentifier($hashid)), new OctetString($certhash), $cv2);

        $attr1 = new Sequence(new ObjectIdentifier("1.2.840.113549.1.9.16.2.47"), new Set(new Sequence(new Sequence($seq3))));
        $attr2 = new Sequence(new ObjectIdentifier("1.2.840.113549.1.9.3"), new Set(new ObjectIdentifier("1.2.840.113549.1.7.1")));
        $attr3 = new Sequence(new ObjectIdentifier("1.2.840.113549.1.9.4"), new Set(new OctetString($hash)));
        //        $attr4 = new Sequence(new ObjectIdentifier("1.2.840.113549.1.9.5"), new Set(new UTCTime(new \DateTimeImmutable('1970-01-01 00:00:00 UTC'))));
        $attr4 = new Sequence(new ObjectIdentifier("1.2.840.113549.1.9.5"), new Set(new UTCTime(new \DateTimeImmutable(date('Y-m-d H:i:s')))));

        $attrs = new ImplicitlyTaggedType(0, new Sequence($attr1, $attr2, $attr3, $attr4));

        $derattrs = (new Set($attr1, $attr2, $attr3, $attr4))->toDER();

        $ahash = \PPOLib\Algo\Hash::gosthash($derattrs);

        $ahash = Util::array2bstr($ahash);

        $sign = $key->sign($ahash);

        $sign = new OctetString($sign);
        $signerinfo = new Sequence($version, new Sequence($cert_issuer, $cert_serial), new Sequence($algoid), $attrs, new Sequence($algoidenc), $sign);

        $signerinfo = new Set($signerinfo);
        $signeddata = new Sequence($version, new Set(new Sequence($algoid)), $data, new ImplicitlyTaggedType(0, new Sequence($cert)), $signerinfo);

        $signeddata = new Sequence($signeddata);
        $signeddata = new ImplicitlyTaggedType(0, $signeddata);

        $signeddataid = new ObjectIdentifier("1.2.840.113549.1.7.2");    //signedData
        $result = new Sequence($signeddataid, $signeddata);
        return $result->toDER();
    }

    /**
     * извлекает  данные  из  сообщения
     *
     * @param mixed $message  входное сообщение
     * @param mixed $onlydata    проверять  цифровую  подпись
     * @return mixed   извлеченные  данные
     */
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
            throw new \Exception("Invalid  sign");
        }
    }

    /**
     * отправка  запроса
     *
     * @param mixed $data   подписаные  данные
     * @param mixed $type   cmd  или  doc
     */
    public static function send($data, $type) {

      //  $fp = fopen(_ROOT.'/logs/curl.txt', 'w');      
      
        $request = curl_init();

        curl_setopt_array($request, [
            CURLOPT_URL => "http://fs.tax.gov.ua:8609/fs/{$type}",
            CURLOPT_POST => true,
            CURLOPT_HEADER => false,
            CURLOPT_HTTPHEADER => array('Content-Type: application/octet-stream', "Content-Length: " . strlen($data)),
         //   CURLOPT_ENCODING => "",
            CURLOPT_RETURNTRANSFER => true,
         //   CURLOPT_CONNECTTIMEOUT => 20,
            CURLOPT_VERBOSE => 1,
       //             CURLOPT_STDERR        => $fp,
                            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_POSTFIELDS => $data
        ]);

        $return = curl_exec($request);

        if (curl_errno($request) > 0) {

            throw new \Exception(curl_error($request));
        }
        curl_close($request);


        return $return;

    }

}
