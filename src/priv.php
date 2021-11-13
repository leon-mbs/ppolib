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
       // $rand = Field::fromString("cff54cbea213c081ed5b13720a00f39b7a2edd3d079194d5ffe807c6d3f19f5cf4c5d0798bbd385f5fb20d316899d2f27a7a521fc04",16) ;
        $hrand = $rand->toString(16);
    // file_put_contents(  "z:/home/local.ppolib/www/data/rand",$hrand);
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

        $tmp_r= Util::hex2array($hr);
        $tmp_s = Util::hex2array($hs);
        
        $mlen = max(array(count($tmp_r),count($tmp_s))) ;
        
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
 
    $buf = array_slice($buf,2) ;
     //   $buf = array_reverse(Util::hex2array($hs . $hr));
        
        
        
        
        $sign = Util::array2bstr($buf);

        //  $pkey = $this->pub() ;
        //  $pkey->verify($message,$sign) ;
        return $sign;
    }
   
}

 /*
 {
  "0": 216,
  "1": 246,
  "2": 247,
  "3": 92,
  "4": 132,
  "5": 94,
  "6": 212,
  "7": 228,
  "8": 7,
  "9": 0,
  "10": 230,
  "11": 140,
  "12": 248,
  "13": 85,
  "14": 163,
  "15": 76,
  "16": 68,
  "17": 1,
  "18": 195,
  "19": 247,
  "20": 153,
  "21": 112,
  "22": 250,
  "23": 205,
  "24": 128,
  "25": 230,
  "26": 33,
  "27": 217,
  "28": 214,
  "29": 82,
  "30": 69,
  "31": 191,
  "32": 228,
  "33": 156,
  "34": 127,
  "35": 230,
  "36": 169,
  "37": 102,
  "38": 104,
  "39": 193,
  "40": 227,
  "41": 66,
  "42": 72,
  "43": 112,
  "44": 227,
  "45": 34,
  "46": 97,
  "47": 57,
  "48": 8,
  "49": 30,
  "50": 251,
  "51": 49,
  "52": 39,
  "53": 12,
 
  "54": 76,
  "55": 120,
  "56": 245,
  "57": 75,
  "58": 147,
  "59": 174,
  "60": 64,
  "61": 175,
  "62": 201,
  "63": 98,
  "64": 135,
  "65": 80,
  "66": 115,
  "67": 177,
  "68": 178,
  "69": 126,
  "70": 160,
  "71": 1,
  "72": 53,
  "73": 196,
  "74": 203,
  "75": 21,
  "76": 78,
  "77": 22,
  "78": 36,
  "79": 32,
  "80": 235,
  "81": 123,
  "82": 52,
  "83": 165,
  "84": 26,
  "85": 179,
  "86": 245,
  "87": 178,
  "88": 64,
  "89": 35,
  "90": 68,
  "91": 224,
  "92": 16,
  "93": 172,
  "94": 61,
  "95": 171,
  "96": 8,
  "97": 88,
  "98": 81,
  "99": 96,
  "100": 37,
  "101": 110,
  "102": 12,
  "103": 53,
  "104": 188,
  "105": 196,
  "106": 125,
  "107": 57,
}
 */