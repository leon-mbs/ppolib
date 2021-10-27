<?php

namespace PPOLib;

use \PPOLib\Util;

/**
* Извлечение  ключа  с  храниища
*/
class KeyStore
{
    /**
    * Извдечение  ключа
    * 
    * @param mixed $keydata    данные  с  файла
    * @param mixed $pass   пароль  к ключу
    * @param Cert $cert  сертификат
    * @return Priv   приватный ключ
    */
    public static function load($keydata, $pass, Cert $cert) {

        $keys = array();

        $seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER($keydata);
    

        //try  pbes

        try {
            $keydata = substr($keydata, 57); //skip pfx header
            $seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER($keydata);
            foreach ($seq as $bag) {
                $uid = $bag->asSequence()->at(0)->asObjectIdentifier()->oid();   //1.2.840.113549.1.12.10.1.2  (PKCS #12 BagIds

                $seq = $bag->asSequence()->at(1)->asTagged()->asImplicit(16)->asSequence();

                $seq = $seq->at(0)->asSequence();
                $cryprData = $seq->at(1)->asOctetString()->string();

                $PBES2 = $seq->at(0)->asSequence()->at(1)->asSequence();

                $keyDerivation = $PBES2->at(0)->asSequence();
                $uid = $keyDerivation->at(0)->asObjectIdentifier()->oid();   //1.2.840.113549.1.5.12 

                $salt = $keyDerivation->at(1)->asSequence()->at(0)->asOctetString()->string();
                $iter = $keyDerivation->at(1)->asSequence()->at(1)->asInteger()->number();

                $encryption = $PBES2->at(1)->asSequence();
                $uid = $encryption->at(0)->asObjectIdentifier()->oid();   //1.2.804.2.1.1.1.1.1.1.3
                $iv = $encryption->at(1)->asSequence()->at(0)->asOctetString()->string();
                $sbox = $encryption->at(1)->asSequence()->at(1)->asOctetString()->string();

                //пароль
                $data = Util::str2array($pass);
                $hash = new \PPOLib\Algo\Hash();

                $key = Util::alloc(32);
                $pw_pad36 = Util::alloc(32, 0x36);
                $pw_pad5C = Util::alloc(32, 0x5C);
                $ins = Util::alloc(4);
                $ins[3] = 1;

                for ($k = 0; $k < count($data); $k++) {
                    $pw_pad36[$k] ^= $data[$k + 1];
                }

                for ($k = 0; $k < count($data); $k++) {
                    $pw_pad5C[$k] ^= $data[$k + 1];
                }

                $hash->update32($pw_pad36);
                $hash->update(Util::str2array($salt));
                $hash->update($ins);
                $h = $hash->finish();
                $hash = new \PPOLib\Algo\Hash();

                $hash->update32($pw_pad5C);
                $hash->update32($h);
                $h = $hash->finish();

                $iter--;
                for ($k = 0; $k < 32; $k++) {
                    $key[$k] = $h[$k];
                }


                while ($iter-- > 0) {
                    $hash = new \PPOLib\Algo\Hash();
                    $hash->update32($pw_pad36);
                    $hash->update32($h);
                    $h = $hash->finish();

                    $hash = new \PPOLib\Algo\Hash();
                    $hash->update32($pw_pad5C);
                    $hash->update32($h);
                    $h = $hash->finish();

                    for ($k = 0; $k < 32; $k++) {
                        $key[$k] ^= $h[$k];
                    }
                }




                $gost = new \PPOLib\Algo\Gost();
                $key = $gost->key($key);

                $cryprData = Util::bstr2array($cryprData);
                $iv = Util::bstr2array($iv);

                $buf = $gost->decrypt_cfb($iv, $cryprData);
                $buf = array_slice($buf, 0, count($cryprData));

                $parsed = Util::array2bstr($buf);

                // file_put_contents(_ROOT . "data/purekey2",$parsed);
                //  $parsed = file_get_contents(_ROOT . "data/purekey2" ) ;


                $seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER($parsed);

                $curveparams = $seq->at(1)->asSequence()->at(1)->asSequence()->at(0)->asSequence();

                $param_d = $seq->at(2)->asOctetString()->string();

                $privkey1 = new Priv($param_d, $curveparams, true);

                $keys[] = $privkey1;
            } //bag
        } catch (\Exception $e) {
            $m = $e->getMessage();
        }

        if(count($keys)==0) {
           //try  IIT
       

          try{

          $uid = $seq->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid()  ;


          if($uid!="1.3.6.1.4.1.19398.1.1.1.2") {  //IIT Store
          throw new  \Exception("Неверное хранилище  ключа");
          }

          $cryptParam = $seq->at(0)->asSequence()->at(1)->asSequence()   ;

          $mac = $cryptParam->at(0)->asOctetString()->string() ;
          $pad = $cryptParam->at(1)->asOctetString()->string() ;


          $cryptData =  $seq->at(1)->asOctetString()->string() ;

          $mac = Util::bstr2array($mac) ;
          $pad = Util::bstr2array($pad) ;
          $cbuf = Util::bstr2array($cryptData) ;



          //конвертим пароль

          $n=10000;
          $data = Util::str2array($pass)   ;
          $hash = new \PPOLib\Algo\Hash();
          $hash->update($data);

          $key = $hash->finish();
          $n--;
          while($n--){
          $hash = new \PPOLib\Algo\Hash();
          $hash->update32($key);

          $key = $hash->finish();

          }


         

          $gost = new \PPOLib\Algo\Gost() ;
          $key = $gost->key($key) ;
          $buf = array_merge($cbuf,$pad) ;
          $buf = $gost->decrypt($buf) ;

          $buf = array_slice($buf,0,count($cbuf)) ;

          // file_put_contents(_ROOT . "data/purekey",$buf);
          //  $keye = file_get_contents(_ROOT . "data/purekey" ) ;

          $seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER(Util::array2bstr($buf)) ;


          $curveparams =    $seq->at(1)->asSequence()->at(1)->asSequence()->at(0)->asSequence();


          $param_d=  $seq->at(2)->asOctetString()->string();
          //  $d1= Util::bstr2array($param_d) ;

          $privkey1 =  new Priv($param_d,$curveparams,true)  ;
          $keys[]=$privkey1;


          $attr = $seq->at(3)->asTagged()->asImplicit(16)->asSequence()  ;

          foreach($attr as $a) {
              $seq = $a->asSequence();
              $uid = $seq->at(0)->asObjectIdentifier()->oid();

              if($uid=='1.3.6.1.4.1.19398.1.1.2.3' ){
              $param_d2=    $seq->at(1)->asSet()->at(0)->asBitString()->string();


              }
              if($uid=='1.3.6.1.4.1.19398.1.1.2.2' ){

                 $curve2 =   $seq->at(1)->asSet()->at(0)->asSequence()->at(0)->asSequence()  ;


              }
          }

          $privkey2 =  new Priv($param_d2,$curve2,false,true)  ;

          $keys[]=$privkey2;


          }  catch( \Exception $e)  {
            $msg = $e->getMessage() ;
          }
                     
        }
        



        $cp = $cert->pub();

        foreach ($keys as $key) {

            $p1 = $key->pub();

            if ($p1->q->isequal($cp->q)) {
              
                return $key;
            }
        }



       throw new \Exception("Invalid key") ;
    }

}

 
  
 