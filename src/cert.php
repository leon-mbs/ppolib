<?php

namespace PPOLib;

use \PPOLib\Util;

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
        $seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER($cert);
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


        return \Sop\ASN1\Type\Constructed\Sequence::fromDER($this->_raw);
    }
 
 //владелец ключа
   public function getOwner() {
        $cert = $this->getAsn1();
        $cer = $cert->at(0)->asSequence();
        
        $cert_issuer = $cer->at(5)->asSequence()->at(0)->asSet()->at(0)->asSequence();

       $is =  $cert_issuer->at(1)->asUTF8String()->string();

        return $is;
    }

    public function getHash() {
        $hash = \PPOLib\Algo\Hash::gosthash($this->_raw);

        return $hash;
    }

}

 