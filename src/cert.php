<?php

namespace PPOLib;

use PPOLib\Util;
use  Sop\ASN1\Type\Constructed\Sequence;
use  Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;

class Cert
{
    private $_publickey;
    private $_dke=[];
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
        $dke = $pki->at(0)->asSequence()->at(1)->asSequence();
        $cnt = count($dke->elements()) ;
        if($cnt>1) {
           $dke = $pki->at(0)->asSequence()->at(1)->asSequence()->at(1)->asOctetString()->string() ;
           $c->_dke = Util::bstr2array($dke);
        }
        
        
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
    public function getOwnerName() {
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
    * @deprecated
    * 
    */
    public function getOwner() {
         return $this->getOwnerName();      
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
    * проверяет    на  использование  для  подписи  и/или  шифрования
    * $op   sign encrypt
    */
    public function isKeyUsage($op='sign') {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $keyid="";
        $ext = $seq->at(7)->asTagged()->asImplicit(16)->asSequence()->at(0)->asSequence();
        
        foreach($ext as $c) {

            $item=   $c->asSequence() ;
            $id = $item->at(0)->asObjectIdentifier()->oid() ;
            if($id=="2.5.29.15") {
                $flag = $item->at(2)->asOctetString()->string();
            
                $bits =  \Sop\ASN1\Type\Primitive\BitString::fromDER($flag)->string();
                $flaga = Util::bstr2array($bits)  ;      
                if( $op=='sign' && ($flaga[0] & 0x80)  == 0x80)  {
                    return  true;
                }
                if( $op=='encrypt' && ($flaga[0] & 0x08)  == 0x08)  {
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
 
    public function getIssuerAndSerial() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
    
        return  new Sequence($seq->at(3)->asSequence(),$seq->at(1)->asInteger()) ;
       
    }   

    /**
    * дата окончания
    * @return mixed timestamp
    */
    public function getEndDate() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $seq = $seq->at(4)->asSequence();
        $t = $seq->at(1)->asUTCTime()->dateTime();
 
         
        return $t->getTimestamp();
    }  

    /**
    * дата начала
    * @return  mixed timestamp
    */
    public function getStartDate() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $seq = $seq->at(4)->asSequence();
        $t = $seq->at(0)->asUTCTime()->dateTime();
 
         
        return $t->getTimestamp();
    }  

    /**
    * алркс  tsp сервера
    * 
    */
    public function getTspLink() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $ret='';
        $ext = $seq->at(7)->asTagged()->asImplicit(16)->asSequence()->at(0)->asSequence();
        
        foreach($ext as $c) {

            $item=   $c->asSequence() ;
            $id = $item->at(0)->asObjectIdentifier()->oid() ;
            if($id=="1.3.6.1.5.5.7.1.11") {
                $str = $item->at(1)->asOctetString()->string();
                
                $seq =  Sequence::fromDER($str);
                $seq=   $seq->at(0)->asSequence() ;
                $id = $seq->at(0)->asObjectIdentifier()->oid() ;
                if($id=='1.3.6.1.5.5.7.48.3') {
                   $ret = $seq->at(1)->asTagged()->asImplicit(4)->asOctetString()->string() ;   
                }
                
                 
      
            }
        }

        return $ret;
    }    
    
    /**
    *   ЄДРПОУ
    * 
    */
    public function getTIN() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $keyid="";
        $ext = $seq->at(7)->asTagged()->asImplicit(16)->asSequence()->at(0)->asSequence();
        
        foreach($ext as $c) {

            $item=   $c->asSequence() ;
            $id = $item->at(0)->asObjectIdentifier()->oid() ;
            if($id=="2.5.29.9") {
                $str = $item->at(1)->asOctetString()->string();
                $el =  Sequence::fromDER($str);
 
                foreach($el as $o) {
                    $seq1 = $o->asSequence() ;
                    $id = $seq1->at(0)->asObjectIdentifier()->oid() ;
                    if($id=='1.2.804.2.1.1.1.11.1.4.2.1') {
                        return $seq1->at(1)->asSet()->at(0)->asPrintableString()->string() ;
                    }
                
                }         
                
            }
        }

        return null;
    }     
    /**
    * ИНН    
    * 
    */
    public function getIPN() {
        $seq =  Sequence::fromDER($this->_raw);
        $seq = $seq->at(0)->asSequence();
        $keyid="";
        $ext = $seq->at(7)->asTagged()->asImplicit(16)->asSequence()->at(0)->asSequence();
        
        foreach($ext as $c) {

            $item=   $c->asSequence() ;
            $id = $item->at(0)->asObjectIdentifier()->oid() ;
            if($id=="2.5.29.9") {
                $str = $item->at(1)->asOctetString()->string();
                $el =  Sequence::fromDER($str);
 
                foreach($el as $o) {
                    $seq1 = $o->asSequence() ;
                    $id = $seq1->at(0)->asObjectIdentifier()->oid() ;
    
                    if($id=='1.2.804.2.1.1.1.11.1.4.1.1') {
                        return $seq1->at(1)->asSet()->at(0)->asPrintableString()->string() ;
                    }
                }         
                
            }
        }

        return null;
    }     
   
    public function getDKE(){
        return $this->_dke;
    } 
    public function asBinary(){
        return $this->_raw;
    } 
    
      
}
 