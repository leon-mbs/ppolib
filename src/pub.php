<?php

namespace PPOLib;

use PPOLib\Util;

/**
* публичный ключ
*/
class Pub
{
    public $q;

    public function __construct($v) {

        if ($v instanceof Field) {
            $p = $v->curve->base->mul($v);
            $this->q = $p->negate();
        }

        if ($v instanceof Point) {

            $this->q = $v;
        }
    }


    /**
    * проверка  ЭЦП
    *
    * @param mixed $message   данные
    * @param mixed $sign    ЭЦП  этих данных
    */
    public function verify($message, $sign) {

        $buf = Util::bstr2array($message);
        $buf = array_reverse($buf);
        $buf = Util::addzero($buf);

        $hv = Field::fromString(Util::array2hex($buf), 16, $this->q->x->curve);

        $buf = Util::array2hex(array_reverse(Util::bstr2array($sign)));
        $rs = str_split($buf, strlen($buf) / 2);

        $rb = Util::array2hex(Util::addzero(Util::hex2array($rs[1])));
        $sb = Util::array2hex(Util::addzero(Util::hex2array($rs[0])));

        $r = Field::fromString($rb, 16);
        $s = Field::fromString($sb, 16);

        $Q = $this->q->mul($r);
        $S = $this->q->x->curve->base->mul($s);
        $pr = $S->add($Q);
        $tt = $pr->x->toString(16) ;
        $ttt = Util::hex2array($tt) ;
        $r1 = $pr->x->mulmod($hv);
        $r1 = $this->q->x->curve->truncate($r1);
        $b = $r1->compare($r);
        return $b == 0;
    }

    
    public function serialize() {
       $f=  $this->q->compress() ;
       $buf = $f->buf8();
       
        $cut=count($buf)  -ceil( $this->q->x->curve->m/8) ;
        $inv=\PPOLib\Util::alloc(count($buf)+2-$cut) ;
        
     
          for ($i = 2; $i < count($inv); $i++) {
            $inv[$i] = $buf[count($buf) + 1 - $i] ??0;
          }
          $inv[0] = 0x04;
          $inv[1] = count($buf) -$cut; 
  
       return $inv;       
       
       
    }
    
    public function keyid() {
       $inv=  $this->serialize() ;
       
       $hash= \PPOLib\Algo\Hash::gosthash($inv) ;
     //  $hash = \PPOLib\Util::array2hex($hash)  ;
       return  $hash;
    }   
}
