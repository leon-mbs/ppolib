<?php

namespace PPOLib;

use \PPOLib\Util;
use \PPOLib\Algo\DSTU7564Mac;
use \PPOLib\Algo\DSTU7624;


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
				if($uid !== '1.2.840.113549.1.12.10.1.2') continue;

                $seq = $bag->asSequence()->at(1)->asTagged()->asImplicit(16)->asSequence();

                $seq = $seq->at(0)->asSequence();
                $cryptData = $seq->at(1)->asOctetString()->string();

                $PBES2 = $seq->at(0)->asSequence()->at(1)->asSequence();

                $keyDerivation = $PBES2->at(0)->asSequence();
                $uid = $keyDerivation->at(0)->asObjectIdentifier()->oid();   //1.2.840.113549.1.5.12 

                $salt = $keyDerivation->at(1)->asSequence()->at(0)->asOctetString()->string();
                $iter = $keyDerivation->at(1)->asSequence()->at(1)->asInteger()->number();

                $encryption = $PBES2->at(1)->asSequence();
				$uid = $encryption->at(0)->asObjectIdentifier()->oid();
				if($uid === '1.2.804.2.1.1.1.1.1.1.3'){ //Старий формат
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

					$cryptData = Util::bstr2array($cryptData);

					$iv = Util::bstr2array($iv);

					$buf = $gost->decrypt_cfb($iv, $cryptData);
					$buf = array_slice($buf, 0, count($cryptData));

					$parsed = Util::array2bstr($buf);

					// file_put_contents(_ROOT . "data/purekey2",$parsed);
					//  $parsed = file_get_contents(_ROOT . "data/purekey2" ) ;
					$seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER($parsed);

					$curveparams = $seq->at(1)->asSequence()->at(1)->asSequence()->at(0);

					$param_d = $seq->at(2)->asOctetString()->string();
					$privkey1 = new Priv($param_d, $curveparams, true);

					$keys[] = $privkey1;
				}
				elseif($uid === '1.2.804.2.1.1.1.1.1.3.5.2'){ //kalyna
					$iv = $encryption->at(1)->asSequence()->at(0)->asOctetString()->string();

					
					
					//$derivedKey = self::pbkdf2_dstu7564kmac($pass, $salt, $iter, 32, 32);
					//pbkdf2_dstu7564kmac($password, $salt, $iterations, $keyLen, $hashLen = 32): string
					//$paddedPassword = str_pad($pass, $hashLen, "\x00", STR_PAD_RIGHT);
					$paddedPassword = str_pad($pass, 32, "\x00", STR_PAD_RIGHT);
					$blocks = 1;//(int)ceil($keyLen / $hashLen);
					$derivedKey = '';
					for ($blockIndex = 1; $blockIndex <= $blocks; $blockIndex++) {
						$blockNumber = pack('N', $blockIndex);
						//$mac = new DSTU7564Mac($hashLen * 8);
						$mac = new DSTU7564Mac(256);
                     
						$mac->init(array_values(unpack('C*', $paddedPassword)));
						$mac->update(array_values(unpack('C*', $salt)));
						$mac->update(array_values(unpack('C*', $blockNumber)));
						$u = pack('C*', ...$mac->finish());
						$t = $u;
						
						for ($j = 1; $j < $iter; $j++) {
							//$mac2 = new DSTU7564Mac($hashLen * 8);
							$mac2 = new DSTU7564Mac(256);
							$mac2->init(array_values(unpack('C*', $paddedPassword)));
							$mac2->update(array_values(unpack('C*', $u)));
							$u = pack('C*', ...$mac2->finish());
							$t = $t ^ $u;
						}
						$derivedKey .= $t;
					}
					$decrypted  = DSTU7624::decryptCbc($cryptData, $derivedKey, $iv);
					$seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER($decrypted);

					$curveparams = $seq->at(1)->asSequence()->at(1)->asSequence()->at(0);
					$param_d = $seq->at(2)->asOctetString()->string();
					$privkey1 = new Priv($param_d, $curveparams, true);

					$keys[] = $privkey1;
					
					
					
					
					//return bin2hex($decrypted);
					//return 'err_invalid_key_'.substr($decrypted, 0, 32); 
					
					
					
					
					
					
					
					
					
					
				}
				else return 'err_invalid_key_'.$uid; 










            } //bag
        } catch (\Exception $e) {
            $m = $e->getMessage();
            return 'err_invalid_key_';
        }

        if (count($keys) == 0) {
            //try  IIT


            try {

                $uid = $seq->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid();

                if ($uid != "1.3.6.1.4.1.19398.1.1.1.2") {  //IIT Store
                    //throw new \Exception("Неверное хранилище  ключа");
                    return 'invalid_key_conteiner';
                }

                $cryptParam = $seq->at(0)->asSequence()->at(1)->asSequence();

                $mac = $cryptParam->at(0)->asOctetString()->string();
                $pad = $cryptParam->at(1)->asOctetString()->string();

                $cryptData = $seq->at(1)->asOctetString()->string();

                $mac = Util::bstr2array($mac);
                $pad = Util::bstr2array($pad);
                $cbuf = Util::bstr2array($cryptData);

                //конвертим пароль

                $n = 10000;
                $data = Util::str2array($pass);
                $hash = new \PPOLib\Algo\Hash();
                $hash->update($data);

                $key = $hash->finish();
                $n--;
                while ($n--) {
                    $hash = new \PPOLib\Algo\Hash();
                    $hash->update32($key);

                    $key = $hash->finish();
                }




                $gost = new \PPOLib\Algo\Gost();
                $key = $gost->key($key);
                $buf = array_merge($cbuf, $pad);
                $buf = $gost->decrypt($buf);

                $buf = array_slice($buf, 0, count($cbuf));

                // file_put_contents(_ROOT . "data/purekey",$buf);
                //  $keye = file_get_contents(_ROOT . "data/purekey" ) ;

                $seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER(Util::array2bstr($buf));

                $curveparams = $seq->at(1)->asSequence()->at(1)->asSequence()->at(0);

                $param_d = $seq->at(2)->asOctetString()->string();
                //  $d1= Util::bstr2array($param_d) ;

                $privkey1 = new Priv($param_d, $curveparams, true);
                $keys[] = $privkey1;

                $attr = $seq->at(3)->asTagged()->asImplicit(16)->asSequence();

                foreach ($attr as $a) {
                    $seq = $a->asSequence();
                    $uid = $seq->at(0)->asObjectIdentifier()->oid();

                    if ($uid == '1.3.6.1.4.1.19398.1.1.2.3') {
                        $param_d2 = $seq->at(1)->asSet()->at(0)->asBitString()->string();
                    }
                    if ($uid == '1.3.6.1.4.1.19398.1.1.2.2') {

                        $curve2 = $seq->at(1)->asSet()->at(0)->asSequence()->at(0);
                    }
                }

                $privkey2 = new Priv($param_d2, $curve2, false, true);

                $keys[] = $privkey2;
            } catch (\Exception $e) {
                //$msg = $e->getMessage();
                return 'invalid_key';
            }
        }


        $cp = $cert->pub();

        foreach ($keys as $key) {

            $p1 = $key->pub();

            if ($p1->q->isequal($cp->q)) {

                return $key;
            }
        }



        //throw new \Exception("Invalid key");
        return 'invalid_cert';
    }

    public static function load_dat($keydata, $pass, Cert $cert) {

        $keys = array();

        $seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER($keydata);

        if (count($keys) == 0) {
            //try  IIT


            try {

                $uid = $seq->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid();

                if ($uid != "1.3.6.1.4.1.19398.1.1.1.2") {  //IIT Store
                    //throw new \Exception("Неверное хранилище  ключа");
                    return 'invalid_key_conteiner';
                }

                $cryptParam = $seq->at(0)->asSequence()->at(1)->asSequence();

                $mac = $cryptParam->at(0)->asOctetString()->string();
                $pad = $cryptParam->at(1)->asOctetString()->string();

                $cryptData = $seq->at(1)->asOctetString()->string();

                $mac = Util::bstr2array($mac);
                $pad = Util::bstr2array($pad);
                $cbuf = Util::bstr2array($cryptData);

                //конвертим пароль

                $n = 10000;
                $data = Util::str2array($pass);
                $hash = new \PPOLib\Algo\Hash();
                $hash->update($data);

                $key = $hash->finish();
                $n--;
                while ($n--) {
                    $hash = new \PPOLib\Algo\Hash();
                    $hash->update32($key);

                    $key = $hash->finish();
                }




                $gost = new \PPOLib\Algo\Gost();
                $key = $gost->key($key);
                $buf = array_merge($cbuf, $pad);
                $buf = $gost->decrypt($buf);

                $buf = array_slice($buf, 0, count($cbuf));

                // file_put_contents(_ROOT . "data/purekey",$buf);
                //  $keye = file_get_contents(_ROOT . "data/purekey" ) ;

                $seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER(Util::array2bstr($buf));

                $curveparams = $seq->at(1)->asSequence()->at(1)->asSequence()->at(0);

                $param_d = $seq->at(2)->asOctetString()->string();
                //  $d1= Util::bstr2array($param_d) ;

                $privkey1 = new Priv($param_d, $curveparams, true);
                $keys[] = $privkey1;

                $attr = $seq->at(3)->asTagged()->asImplicit(16)->asSequence();

                foreach ($attr as $a) {
                    $seq = $a->asSequence();
                    $uid = $seq->at(0)->asObjectIdentifier()->oid();

                    if ($uid == '1.3.6.1.4.1.19398.1.1.2.3') {
                        $param_d2 = $seq->at(1)->asSet()->at(0)->asBitString()->string();
                    }
                    if ($uid == '1.3.6.1.4.1.19398.1.1.2.2') {

                        $curve2 = $seq->at(1)->asSet()->at(0)->asSequence()->at(0);
                    }
                }

                $privkey2 = new Priv($param_d2, $curve2, false, true);

                $keys[] = $privkey2;
            } catch (\Exception $e) {
                //$msg = $e->getMessage();
                return 'invalid_key'.$e->getMessage();
            }
        }


        $cp = $cert->pub();

        foreach ($keys as $key) {

            $p1 = $key->pub();

            if ($p1->q->isequal($cp->q)) {

                return $key;
            }
        }



        //throw new \Exception("Invalid key");
        return 'invalid_cert';
    }

    /**
     *  извлечение  ключа и сертификата  из  jks  хпанилища
     */
    public static function loadjks($keydata, $pass) {

        $loader = new JKS($keydata, $pass);
        if($loader->errmsg) return [$loader->errmsg,null];
        
        return  $loader->getData();
        
    }

}

class JKS
{

    private $keys = array();
    private $certs = array();
    private $jksdata;
    private $pass;
    private $pos = 0;
    public $errmsg;

    public function __construct($jksdata, $pass) {
        $this->jksdata = Util::bstr2array($jksdata);
        $this->pass = $pass;

        $test = $this->U32();
        if ($test != 0xfeedfeed) {  //4277010157
            //throw new \Exception("Invalid jks");
            $this->errmsg='invalid_key_conteiner';
            return;
        }
        $ver = $this->U32();
        if ($ver != 2) {
            //throw new \Exception("Invalid jks");
            $this->errmsg='invalid_key_conteiner';
            return;
        }
        $entries = $this->U32();

        for ($i = 0; $i < $entries; $i++) {
            $tag = $this->U32();
            if ($tag == 1) {
                $this->readKey();
                if($this->errmsg) return;
            }
            if ($tag == 2) {
                $c = $this->readCert();
                if($this->errmsg) return;

                $this->certs[] = Cert::load($c['data']);
            }
        }
    }

    //возвращает  ключ  и соответствующий сертификат
    public function getData() {
        //сравниваем  публичные  ключи
        foreach($this->keys as $key){
          $pubk = $key->pub();
          foreach($this->certs as $cert){
              
             $cpub = $cert->pub(); 
             if ($pubk->q->isequal($cpub->q)) {
                    
                    return array( $key, $cert);
              }       
              
          }
        }
    
        
    }
    private function U32() {

        $ret = ($this->jksdata[$this->pos] * 0x1000000 ) +
                ($this->jksdata[$this->pos + 1] << 16 ) +
                ($this->jksdata[$this->pos + 2] << 8 ) +
                ($this->jksdata[$this->pos + 3] );

        $this->pos += 4;
        return $ret;
    }

    private function U16() {

        $ret = ($this->jksdata[$this->pos] << 8 ) |
                ($this->jksdata[$this->pos + 1] );

        $this->pos += 2;
        return $ret;
    }

    private function BIN($len) {

        $ret = array_slice($this->jksdata, $this->pos, $len);

        $this->pos += $len;
        return $ret;
    }

    private function STR($len) {
        $ret = $this->BIN($len);
        $ret = Util::array2bstr($ret);
        return $ret;
    }

    private function readKey() {
        $name = $this->STR($this->U16());
        $this->U32(); // skip timestamp high
        $this->U32(); // skip timestamp low
        $key_data = $this->BIN($this->U32());

        $key_data = array_slice($key_data, 0x18); // drop header
        // $this->keys[]= Util::array2bstr($key_data) ;

        $dk = $this->decode($key_data);
        try {
            $seq = \Sop\ASN1\Type\Constructed\Sequence::fromDER(Util::array2bstr($dk));
        } catch (\Exception $e) {
            $this->errmsg='invalid_key';
            return;
        }
        
        
             $curveparams = $seq->at(1)->asSequence()->at(1)->asSequence()->at(0);

                $param_d = $seq->at(2)->asOctetString()->string();
                //  $d1= Util::bstr2array($param_d) ;

                $privkey1 = new Priv($param_d, $curveparams, true);
                $this->keys[]= $privkey1;
              
                $attr = $seq->at(3)->asTagged()->asImplicit(16)->asSequence();

                foreach ($attr as $a) {
                    $seq = $a->asSequence();
                    $uid = $seq->at(0)->asObjectIdentifier()->oid();

                    if ($uid == '1.3.6.1.4.1.19398.1.1.2.3') {
                        $param_d2 = $seq->at(1)->asSet()->at(0)->asBitString()->string();
                    }
                    if ($uid == '1.3.6.1.4.1.19398.1.1.2.2') {

                        $curve2 = $seq->at(1)->asSet()->at(0)->asSequence()->at(0);
                    }
                }

                $privkey2 = new Priv($param_d2, $curve2, false, true);
                $this->keys[]= $privkey2;
  
        
        
        $chain = $this->U32();

        for ($i = 0; $i < $chain; $i++) {
            $r = $this->readCert();
            if ($r['type'] == "X.509") {
                $this->certs[] = Cert::load($r['data']);
            }
        }
    }

    private function readCert() {
        $type = $this->STR($this->U16());
        $data = $this->BIN($this->U32());
        return array('type' => $type, 'data' => Util::array2bstr($data));
    }

    private function decode($key_data) {
        $pass = Util::bstr2array($this->pass);
        $pw = Util::alloc(count($pass));
        for ($i = 0; $i < strlen($this->pass); $i++) {
            $code = $pass[$i];
            $pw[$i * 2] = ( $code & 0xFF00) >> 8;
            $pw[($i * 2) + 1] = ( $code & 0xFF);
        }
        $ll = count($key_data);
        $data = array_slice($key_data, 20, count($key_data) - 40);
        $iv = array_slice($key_data, 0, 20);
        $check = array_slice($key_data, count($key_data) - 20);
        $cur = $iv;
        $length = count($data);
        $open = Util::alloc($length);

        $pos = 0;

        while ($pos < $length) {
           // $hash = new \PPOLib\Algo\SHA1();
          //  $hash->update($pw);
          //  $hash->update($cur);
          //  $cur = $hash->digest();

            $c = Util::concat_array($pw,$cur) ;
            
            $t1= sha1(Util::array2bstr($c))  ;
            $cur = Util::hex2array($t1)  ;
               
            for ($i = 0; $i < count($cur); $i++) {
                if($pos >= $length) break;
                //$open[$pos] = $data[$pos] ^ $cur[$i];
				$open[$pos] = ($data[$pos]?? 0)^ $cur[$i];
                $pos++;
            }
        }

        $open = array_slice($open, 0, $length);

      //  $toCheck = new \PPOLib\Algo\SHA1();
      //  $toCheck->update($pw);
      //  $toCheck->update($open);
       // $digest = $toCheck->digest();

            $c = Util::concat_array($pw,$open) ;
            
            $t1= sha1(Util::array2bstr($c))  ;
            $digest = Util::hex2array($t1)  ;
            
        
        
        //проверка
        for ($i = 0; $i < count($check); $i++) {
           if($digest[$i] != $check[$i]) {
              //throw new \Exception("Invalid jks key or password");
              $this->errmsg='invalid_key';
              return;
           }; 
        }

     
          return $open;
    }

}
