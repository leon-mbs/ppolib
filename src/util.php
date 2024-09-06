<?php

namespace PPOLib;

use PPOLib\Algo\Hash;

/**
* вспомогательный функции
*/
class Util
{
    public static function hex2array($hex, $to8 = false) {
        if((strlen($hex) %2)==1) {
            $hex = '0'.$hex;
        }
        $s = str_split($hex, 2);
        $a = array();
        for ($i = 0; $i < count($s); $i++) {
            $a[$i] = hexdec($s[$i]);
        }
        if ($to8) {
            $c = 8 - count($a) % 8;

            for ($i = 0; $i < $c; $i++) {
                $a = array_merge($a, array(0));
            }
        }

        return $a;
    }

    public static function array2hex($a) {

        $ss = "";
        foreach ($a as $v) {
            $ss .= sprintf("%02X", $v);
        }
        return $ss;
    }

    public static function norm32($r) {
        if(PHP_INT_SIZE!=8) {
            return $r;
        }

        $r = $r & 0xFFFFFFFF;
        if ($r & 0x80000000) {
            $r = $r & ~0x80000000;
            $r = -2147483648 + $r;
        }
        return  $r;
    }
    //аналог >>>
    public static function rrr($a, $b) {

        $a = Util::norm32($a);

        if ($b >= 32 || $b < -32) {
            $m = (int) ($b / 32);
            $b = $b - ($m * 32);
        }

        if ($b < 0) {
            $b = 32 + $b;
        }

        if ($b == 0) {
            return (($a >> 1) & 0x7fffffff) * 2 + (($a >> $b) & 1);
        }
        $s = "".$a;
        if(PHP_INT_SIZE==8 && $a  > 0x7fffffff) {

            $a  =  $a - 0xffffffff -1 ;


        }

        if ($a < 0) {
            $a = ($a >> 1);
            $a &= 0x7fffffff;
            $a |= 0x40000000;
            //  $a = ($a >> ($b - 1));

            $s = decbin($a);

            $l = strlen($s);
            $cut = $l-($b - 1) ;
            if($cut >0) {
                $s ="0". substr($s, 0, $l-($b - 1));
            } else {
                $s="0";
            }

            $a = bindec($s)  ;


        } else {

            // $a = ($a >> $b);

            $s = decbin($a);

            $l = strlen($s);
            $cut = $l-$b ;
            if($cut >0) {
                $s ="0". substr($s, 0, $l-$b);
            } else {
                $s="0";
            }

            $a = bindec($s)  ;

        }
        return $a;
    }

    public static function ll($a, $b) {

        $a = Util::norm32($a);

        if(PHP_INT_SIZE==8 && $a > 0) {




            $s = decbin($a);
            $s = $s. str_repeat('0', $b);
            $l  =strlen($s);

            $a = bindec($s) ;
            $a &= 0xffffffff;
            if($a  > 0x7fffffff) {
                $s = "". $a;
                $a  =  $a - 0xffffffff -1 ;
                $ss = "". $a;

            }

            return  $a;
        }
        return $a << $b ;
    }

    public static function str2array($str, $to8 = false) {
        $a = unpack('C*', $str);

        if ($to8) {
            $c = 8 - count($a) % 8;

            for ($i = 0; $i < $c; $i++) {
                $a = array_merge($a, array(0));
            }
        }
        return $a;
    }

    public static function alloc($length, $v = 0,$rand=false) {
        $a = array();
        for ($i = 0; $i < $length; $i++) {
            $a[$i] = $v;
            if($rand) {
               $a[$i] = rand(0,255); 
            }
        }
        return $a;
    }

    public static function bstr2array($str, $to8 = false) {
        $a = array();
        foreach (str_split($str, 1) as $c) {

            $a[] = ord($c);
        }

        if ($to8) {
            $c = 8 - count($a) % 8;

            for ($i = 0; $i < $c; $i++) {
                $a = array_merge($a, array(0));
            }
        }
        return $a;
    }

    public static function array2bstr($array) {

        $bstr = pack('H*', Util::array2hex($array));
        ;
        return $bstr;
    }

    /*

      public static function convert_password($pass,$n=10000){
      $data = Util::str2array($pass)   ;
      $hash = new Hash();
      $hash->update($data);

      $ret = $hash->finish();
      $n--;
      while($n--){
      $hash = new Hash();
      $hash->update32($ret);

      $ret = $hash->finish();

      }
      return $ret;
      }
     */

    public static function invert($in) {

        $ret = array();
        for ($i = count($in) - 1; $i >= 0; $i--) {
            $cr = $in[$i];
            $cr = (
                $cr >> 7 | ($cr >> 5) & 2 | ($cr >> 3) & 4 | ($cr >> 1) & 8 | ($cr << 1) & 16 | ($cr << 3) & 32 | ($cr << 5) & 64 | ($cr << 7) & 128
            );
            $ret[] = $cr;
        }

        return $ret;
    }

    public static function addzero($in, $reorder = false) {

        $ret = array();

        if ($reorder !== true) {
            $ret[] = 0;
        }
        for ($i = 0; $i < count($in); $i++) {
            $ret[] = $in[$i];
        }

        if ($reorder === true) {
            $ret[] = 0;
            $ret = array_reverse($ret);
        }
        return $ret;
    }

    public static function concat_array($a1, $a2) {
        $r = array();
        if(is_array($a1)) {
            foreach($a1 as $i) {
                $r[]=$i;
            }
        }
        if(is_array($a2)) {
            foreach($a2 as $i) {
                $r[]=$i;
            }
        }

        return $r;
    }

}
