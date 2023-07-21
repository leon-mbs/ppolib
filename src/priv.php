<?php

namespace PPOLib;

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


        // $r = Field::fromString($br,2,$this->d->curve)  ;
        // $tmp_r= Util::hex2array($hr);

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

}
