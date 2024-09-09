<?php
 
namespace PPOLib;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Tagged\ImplicitlyTaggedType;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\Primitive\BitString;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use PPOLib\Util;

/**
* приватный ключ
*/
class Priv
{
    public $d;

    public function __construct($d, $curve, $le = false, $inv = false) {
        $c = new Curve($curve, $le);
        $d = Util::bstr2array($d);
        if ($le) {
            $d = array_reverse($d);
        }
        if ($inv) {
            $d = Util::addzero(Util::invert($d));
        }

        $this->d = Field::fromString(Util::array2hex($d), 16, $c);
    }


    /**
    * возвращает публичный  ключ
    *
    */
    public function pub() {


        return new Pub($this->d);
    }


    /**
    * подпись  данных
    * возвращает  ЭЦП
    * @param mixed $message
    */
    public function sign($message) {
        $buf = Util::bstr2array($message);
        $buf = array_reverse($buf);
        $buf = Util::addzero($buf);

        $hv = Field::fromString(Util::array2hex($buf), 16, $this->d->curve);
        $h44 = $hv->toString(16);

        $rand = $this->d->curve->random();
        // $rand = Field::fromString("cff54cbea213c081ed5b13720a00f39b7a2edd3d079194d5ffe807c6d3f19f5cf4c5d0798bbd385f5fb20d316899d2f27a7a521fc04",16) ;
        $hrand = $rand->toString(16);

        $eG = $this->d->curve->base->mul($rand);
        $h = $eG->x->toString(16);

        $r = $hv->mulmod($eG->x);
        $hrb = $r->toString(16);
        $r = $this->d->curve->truncate($r);
        $hr = $r->toString(16);

        $s = $this->d->mul($r);
        $sh = $r->toString(16);
        $sb = gmp_mul($this->d->value, $r->value);

        $s->value = gmp_mod($sb, $this->d->curve->order->value);

        $sh = $r->toString(16);
        $s->value = gmp_add($s->value, $rand->value);

        $s->value = gmp_mod($s->value, $this->d->curve->order->value);

        $sh = $s->toString(16);
        $s->value = gmp_mod($s->value, $this->d->curve->order->value);
        
       
        $hs = $s->toString(16);
        $hr = $r->toString(16);

        if(strlen($hs) < 64){
             while(strlen($hs) < 64) $hs ='0'.$hs;
        }          
        if(strlen($hr) < 64){
             while(strlen($hr) < 64) $hr ='0'.$hr;
        }          
/*
        $tmp_r1= Util::hex2array($hr);


        //восстанавливаем  возможные  0 после  truncate
        $br = $r->toString(2);
        $ol = $this->d->curve->order->getLength() ;

        while(strlen($br)    < $ol) {
            $br = '0'.$br;
        }
        //дополняем  до  кратного 8
        $l = strlen($br) ;
        $lb = intval($l/8) ;
        if(($l % 8) >0) {
            $lb++ ;
        }

        while(strlen($br)    < ($lb*8)) {
            $br = '0'.$br;
        }

        $spl = str_split($br, 8) ;
        $tmp_r = array();
        foreach($spl as $chunk) {
            $tmp_r[]=  base_convert($chunk, 2, 10) ;
        }
        */

        // $r = Field::fromString($br,2,$this->d->curve)  ;
        
        $tmp_r= Util::hex2array($hr);
        $tmp_s = Util::hex2array($hs);

        $mlen = max(array(count($tmp_r),count($tmp_s))) ;
        $buf = Util::alloc($mlen*2+2) ;
        $buf[0]=4;
        $buf[1]=$mlen*2;

        for ($idx = 0; $idx < $mlen; $idx++) {
            $tmp = $tmp_r[$mlen - $idx - 1];
            $buf[$idx+2] =  $tmp <0 ? 256+$tmp : $tmp;
        }

        for ($idx = 0; $idx < $mlen; $idx++) {
            $tmp = $tmp_s[$mlen - $idx - 1];
            $buf[$idx+2+$mlen] =  $tmp <0 ? 256+$tmp : $tmp;
        }

        $buf = array_slice($buf, 2) ;

        $signh = Util::array2hex($buf);
        $sign = Util::array2bstr($buf);

        //  $pkey = $this->pub() ;
        //  $pkey->verify($message,$sign) ;
        return $sign;
    }

    public function encrypt($message,Cert $forcert) {
        $buf = Util::bstr2array($message);
           
        $cek = Util::alloc(32,0,true);
        $ukm = Util::alloc(64,0,true);
        $iv  = Util::alloc(8,0,true);
        
//$cek =[235, 70, 25, 37, 91, 135, 44, 22, 113, 11, 108, 51, 210, 133, 173, 124, 174, 118, 206, 2, 16, 197, 135, 179, 219, 233, 14, 107, 236, 144, 85, 86];
//$ukm=[240, 38, 197, 91, 140, 161, 171, 196, 63, 147, 48, 155, 80, 72, 41, 91, 158, 215, 54, 29, 42, 156, 131, 129, 56, 118, 178, 89, 140, 97, 221, 46, 56, 52, 22, 107, 125, 29, 69, 143, 245, 73, 212, 17, 142, 158, 187, 129, 206, 202, 250, 224, 74, 203, 82, 139, 101, 235, 168, 151, 254, 237, 97, 240];
//$iv=[255, 68, 42, 235, 191, 125, 160, 219];
        
        
        $kek=$this->sharedKey($forcert->pub(),$ukm) ;
        $wcek=$this->keywrap($kek, $cek, $iv);
      
        $ctext = \PPOLib\Algo\Gost::gost_crypt(0,$buf,$cek,$iv) ;
        
        $ret=[];
        $ret['iv'] = $iv  ;
        $ret['wcek'] = $wcek ;  
        $ret['data'] = $ctext  ;  
        $ret['ukm'] = $ukm ;
        
        return $ret;
    }

    public function keywrap($kek, $cek, $iv){  
       $cekicv = Util::alloc(40);
       $temp2 =  Util::alloc(44) ;
       $temp3 =  Util::alloc(48) ;
       $gost  =  new \PPOLib\Algo\Gost() ;
       $gost->key($kek) ;
       $icv = $gost->mac(32, $cek);
   
        for ($idx=0; $idx < 32; $idx++) {
            $cekicv[$idx] = $cek[$idx];
        }
        for ($idx=32; $idx < 40; $idx++) {
            $cekicv[$idx] = $icv[$idx - 32] ?? 0;
        }      
    
        $temp1 =  $gost->crypt_cfb($iv, $cekicv);
     
        for ($idx=0; $idx < 8; $idx++) {
           $temp2[$idx] = $iv[$idx];
        }
        for ($idx=8; $idx < 44; $idx++) {
            $temp2[$idx] = $temp1[$idx - 8];
        }

        for($idx=0; $idx < 48; $idx++) {
            $temp3[$idx] = $temp2[44 - $idx - 1] ?? 0;
        }    
     
        $result =  $gost->crypt_cfb([   0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05], $temp3);
        
        return array_slice($result,0,44)  ; 
 
   
    }
    
    public function sharedKey(Pub $pub,$ukm) {
        $zz = $this->derive($pub) ;
        if($zz[0]==0) {
            $zz = array_slice($zz,1) ;
        }
        $counter = [0,0,0,1] ;
        
        $salt = $this->salt($ukm) ;
        $kek_input = Util::alloc(count($zz)+count($counter)+ count($salt)) ;       
        $kek_input= array_merge($zz,$counter,$salt)  ;
        $kek_input = \PPOLib\Algo\Hash::gosthash($kek_input);
        return $kek_input;
    }

    public function derive(Pub $pub ) {
        $pointQ = $pub->q;
        $kf = Field::fromInt($this->d->curve->kofactor[0] );
           
 
        $pointZ = $pointQ->mul($this->d->mulmod($kf)); 
        $b = $pointZ->x->toString(16) ;
        $bufZZ = Util::hex2array($b) ;
        $cut= count($bufZZ)   - ceil($this->d->curve->m/8) ;
        return array_slice($bufZZ,$cut) ;
    }
    
    public function salt($ukm) {
     
        $dataid = new ObjectIdentifier("1.2.804.2.1.1.1.1.1.1.5");  
        $data = new Sequence($dataid,new \Sop\ASN1\Type\Primitive\NullType()) ;
        
        $s1 = new OctetString(Util::array2bstr($ukm));
        $s1 = new Sequence($s1);
        $s1 = new ImplicitlyTaggedType(0, $s1);
        $s2 = new OctetString(Util::array2bstr([0,0,1,0]));
        $s2 = new Sequence($s2);
        $s2 = new ImplicitlyTaggedType(2, $s2);
        $data = new Sequence($data,$s1,$s2) ;
        $ret=$data->toDER()  ;

        return Util::bstr2array($ret );
    } 
    
    
    public function decrypt($data,Pub $pub,$p) {
        
        $kek= $this->sharedKey($pub,$p['ukm']) ;
        $cek= $this->keyunwrap($kek, $p['wcek']) ;
        $dec= \PPOLib\Algo\Gost::gost_crypt(1,$data,$cek,$p['iv']) ; 
        $dec = array_slice($dec,0,count($data))  ;     
        return Util::array2bstr($dec)  ;
    } 
    
    public function keyunwrap($kek,   $wcek){  
       $gost  =  new \PPOLib\Algo\Gost() ;
       $gost->key($kek);  
       
       $icv = Util::alloc(4) ;
       $iv = Util::alloc(8) ;
       $temp1 = Util::alloc(40) ;
       $temp2 = Util::alloc(44) ;
       $temp3 = $gost->decrypt_cfb([ 0x4a, 0xdd, 0xa2, 0x2c, 0x79, 0xe8, 0x21, 0x05], $wcek);
      
       
        for($idx=0; $idx < 44; $idx++) {
            $temp2[$idx] = $temp3[44 - $idx - 1];
        }

        for ($idx = 0; $idx < 8; $idx++ ) {
            $iv[$idx] = $temp2[$idx];
        }
        for ($idx = 0; $idx < 36; $idx++) {
            $temp1[$idx] = $temp2[$idx + 8];
        }

        $cekicv = $gost->decrypt_cfb($iv, $temp1);
        for ($idx = 0; $idx < 4; $idx++) {
            $icv[$idx] = $cekicv[$idx + 32];
        }

        $icv_check = $gost->mac(32, array_slice($cekicv,0, 32));
  
        $err =  $icv[0] ^ $icv_check[0];
        $err |= $icv[1] ^ $icv_check[1];
        $err |= $icv[2] ^ $icv_check[2];
        $err |= $icv[3] ^ $icv_check[3];        
        
        if($err !== 0) {
            throw new \Exception('Invalid decode');
        }
        
        return array_slice($cekicv,0, 32);
    }
   
}
