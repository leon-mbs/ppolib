<?php

namespace PPOLib;

use PPOLib\Util;
use  Sop\ASN1\Type\Constructed\Sequence;
use  Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;

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

 

        $algo = $seq->at(2)->asSequence()->at(0)->asObjectIdentifier()->oid();
        $pki = $seq->at(6)->asSequence();

        $algo = $pki->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid();
        $curveparam = $pki->at(0)->asSequence()->at(1)->asSequence()->at(0) ;
        $curve = new Curve($curveparam, true);

        $pkey = $pki->at(1)->asBitString()->string();
        $a = Util::bstr2array($pkey);
        $a = array_slice($a, 2);
        $a = array_reverse($a);
        $aa =  Util::array2hex($a) ;
        $p = Field::fromString(Util::array2hex($a), 16, $curve);
        $ph = $p->toString(16)  ;
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


    /**
    * Имя  владельца  сертификата
    *
    */
    public function getOwner() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $owner="";
        $cert_issuer = $seq->at(5)->asSequence();
        foreach($cert_issuer as $c) {
            $set = $c->asSet()  ;
            $id = $set->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid() ;
            if($id=="2.5.4.3") {    // 2.5.4.10
                $owner = $set->at(0)->asSequence()->at(1)->asUTF8String()->string();
                break;
            }
        }

        return $owner;
    }

    /**
    * возвращает  идентификатор  ключа
    *
    */
    public function getKeyId() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $keyid="";
        $ext = $seq->at(7)->asTagged()->asImplicit(16)->asSequence()->at(0)->asSequence();
        ;
        foreach($ext as $c) {

            $item=   $c->asSequence() ;
            $id = $item->at(0)->asObjectIdentifier()->oid() ;
            if($id=="2.5.29.14") {
                $keyid = $item->at(1)->asOctetString()->string();
                $keyid = substr($keyid, 2) ;

                $h=   Util::array2hex(Util::bstr2array($keyid))   ;
                $keyid = strtolower($h)  ;
                break;
            }
        }

        return $keyid;
    }

    /**
    * проверяет  keyusage
    * 
    */
    public function isKeyUsage() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $keyid="";
        $ext = $seq->at(7)->asTagged()->asImplicit(16)->asSequence()->at(0)->asSequence();
        
        foreach($ext as $c) {

            $item=   $c->asSequence() ;
            $id = $item->at(0)->asObjectIdentifier()->oid() ;
            if($id=="2.5.29.15") {
                $flag = $item->at(2)->asOctetString()->string();
                $flaga = Util::bstr2array($flag)  ;

                if($flaga[3] == 192)  {
                    return  true;
                }
                
            }
        }

        return false;
    }    
  
  
    /**
    * возвращает серийный  номер
    * 
    */
    public function getSerial() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
    
        $serial = $seq->at(1)
                ->asInteger()
                ->number();

        return $serial;
    }   

    /**
    * дата окончания
    * @return  timestamp
    */
    public function getEndDate() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $seq = $seq->at(4)->asSequence();
        $t = $seq->at(1)->asUTCTime()->dateTime();
 
         
        return $t->getTimestamp();
    }  
    
}
