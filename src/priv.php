<?php

namespace PPOLib;

use \PPOLib\Util;

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
        //  $rand = Field::fromString("690b17cd92dbb5c7b96a988de42401188895c4ca0267fb6c42ab68edb556e59e",16) ;


        $eG = $this->d->curve->base->mul($rand);
        $h = $eG->x->toString(16);

        $r = $hv->mulmod($eG->x);
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

        $hr = $r->toString(16);
        $hs = $s->toString(16);

        $ra = Util::hex2array($hr);
        $sa = Util::hex2array($hs);
        $buf = array_reverse(Util::hex2array($hs . $hr));
        
        $sign = Util::array2bstr($buf);

        //  $pkey = $this->pub() ;
        //  $pkey->verify($message,$sign) ;
        return $sign;
    }

}

 