<?php

namespace PPOLib\Algo;

use PPOLib\Util;

// блочное шифрование
class Gost
{
    public $k = array();
    public $k87 = array();
    public $k65 = array();
    public $k43 = array();
    public $k21 = array();
    public $n = array();
    public $gamma = array();

    public function __construct() {
        $box = new SBox();
        $this->boxinit($box);
    }

    public function boxinit($box) {
        for ($i = 0; $i < 256; $i++) {
            //$r = Util::rrr($i, 4);    //optimize
            $r = $i >> 4;

            $this->k87[$i] = (($box->k8[$r] << 4) | $box->k7[$i & 15]) << 24;
            $this->k65[$i] = (($box->k6[$r] << 4) | $box->k5[$i & 15]) << 16;
            $this->k43[$i] = (($box->k4[$r] << 4) | $box->k3[$i & 15]) << 8;
            $this->k21[$i] = ($box->k2[$r] << 4) | $box->k1[$i & 15];

            if(PHP_INT_SIZE==8 && $this->k87[$i]  > 0x7fffffff) {
                $this->k87[$i]=   $this->k87[$i] -0xffffffff -1 ;

            }

        }

    }

    public function key($k): void {

        for ($i = 0, $j = 0; $i < 8; $i++, $j += 4) {
            $this->k[$i] = $k[$j] | ($k[$j + 1] << 8) | ($k[$j + 2] << 16) | ($k[$j + 3] << 24);
            if ($this->k[$i] < 0) {
                $this->k[$i] = 0xFFFFFFFF + 1 + $this->k[$i];
            }
        }
    }

    public function pass($x) {
        /*  $x =
          $this->k87[Util::rrr($x, 24) & 255] |
          $this->k65[Util::rrr($x, 16) & 255] |
          $this->k43[Util::rrr($x, 8) & 255] |
          $this->k21[$x & 255];          //optimize
         */

        $x = $this->k87[($x >> 24) & 255] |
                $this->k65[($x >> 16) & 255] |
                $this->k43[($x >> 8) & 255] |
                $this->k21[$x & 255];



        /* Rotate left 11 bits */


        $x = ($x << 11) | Util::rrr($x, (32 - 11));


        return $x & 0xffffffff;
    }

    public function crypt($clear) {
        if (is_string($clear)) {
            $clear = Util::str2array($clear);
        }


        $blocks = ceil(count($clear) / 8);
        $out = array();
        $idx = 0;

        while ($idx < $blocks) {
            $off = $idx++ * 8;
            $block = array_slice($clear, $off, 8);
            $outblock = $this->crypt64($block);
            $out = array_merge($out, $outblock);
        }

        if (count($out) !== count($clear)) {
            $out = array_slice($out, 0, count($clear));
        }
        return $out;
    }

    public function crypt64($clear) {


        $n = array();
        $n[0] = $clear[0] | ($clear[1] << 8) | ($clear[2] << 16) | ($clear[3] << 24);
        $n[1] = $clear[4] | ($clear[5] << 8) | ($clear[6] << 16) | ($clear[7] << 24);

        $n[1] ^= $this->pass($n[0] + $this->k[0]);
        $n[0] ^= $this->pass($n[1] + $this->k[1]);
        $n[1] ^= $this->pass($n[0] + $this->k[2]);
        $n[0] ^= $this->pass($n[1] + $this->k[3]);
        $n[1] ^= $this->pass($n[0] + $this->k[4]);
        $n[0] ^= $this->pass($n[1] + $this->k[5]);
        $n[1] ^= $this->pass($n[0] + $this->k[6]);
        $n[0] ^= $this->pass($n[1] + $this->k[7]);

        $n[1] ^= $this->pass($n[0] + $this->k[0]);
        $n[0] ^= $this->pass($n[1] + $this->k[1]);
        $n[1] ^= $this->pass($n[0] + $this->k[2]);
        $n[0] ^= $this->pass($n[1] + $this->k[3]);
        $n[1] ^= $this->pass($n[0] + $this->k[4]);
        $n[0] ^= $this->pass($n[1] + $this->k[5]);
        $n[1] ^= $this->pass($n[0] + $this->k[6]);
        $n[0] ^= $this->pass($n[1] + $this->k[7]);

        $n[1] ^= $this->pass($n[0] + $this->k[0]);
        $n[0] ^= $this->pass($n[1] + $this->k[1]);
        $n[1] ^= $this->pass($n[0] + $this->k[2]);
        $n[0] ^= $this->pass($n[1] + $this->k[3]);
        $n[1] ^= $this->pass($n[0] + $this->k[4]);
        $n[0] ^= $this->pass($n[1] + $this->k[5]);
        $n[1] ^= $this->pass($n[0] + $this->k[6]);
        $n[0] ^= $this->pass($n[1] + $this->k[7]);

        $n[1] ^= $this->pass($n[0] + $this->k[7]);
        $n[0] ^= $this->pass($n[1] + $this->k[6]);
        $n[1] ^= $this->pass($n[0] + $this->k[5]);
        $n[0] ^= $this->pass($n[1] + $this->k[4]);
        $n[1] ^= $this->pass($n[0] + $this->k[3]);
        $n[0] ^= $this->pass($n[1] + $this->k[2]);
        $n[1] ^= $this->pass($n[0] + $this->k[1]);
        $n[0] ^= $this->pass($n[1] + $this->k[0]);

        $out = array();
        $out[0] = $n[1] & 0xff;
        $out[1] = Util::rrr($n[1], 8) & 0xff;
        $out[2] = Util::rrr($n[1], 16) & 0xff;
        $out[3] = Util::rrr($n[1], 24);
        $out[4] = $n[0] & 0xff;
        $out[5] = Util::rrr($n[0], 8) & 0xff;
        $out[6] = Util::rrr($n[0], 16) & 0xff;
        $out[7] = Util::rrr($n[0], 24);


        return $out;      //216 205 110 128 165 137 175 83
    }

    public function decrypt($cypher) {
        $blocks = ceil(count($cypher) / 8);
        $out = array();

        while ($blocks--) {
            $off = $blocks * 8;
            $block = array_slice($cypher, $off, 8);
            $outblock = $this->decrypt64($block);
            $out = array_merge($outblock, $out);
        }

        if (count($out) !== count($cypher)) {
            $out = array_slice($out, 0, count($cypher));
        }
        return $out;
    }

    public function decrypt64($cypher) {
        $n = array();
        $n[0] = $cypher[0] | ($cypher[1] << 8) | ($cypher[2] << 16) | ($cypher[3] << 24);
        $n[1] = $cypher[4] | ($cypher[5] << 8) | ($cypher[6] << 16) | ($cypher[7] << 24);

        $n[1] ^= $this->pass($n[0] + $this->k[0]);
        $n[0] ^= $this->pass($n[1] + $this->k[1]);
        $n[1] ^= $this->pass($n[0] + $this->k[2]);
        $n[0] ^= $this->pass($n[1] + $this->k[3]);
        $n[1] ^= $this->pass($n[0] + $this->k[4]);
        $n[0] ^= $this->pass($n[1] + $this->k[5]);
        $n[1] ^= $this->pass($n[0] + $this->k[6]);
        $n[0] ^= $this->pass($n[1] + $this->k[7]);

        $n[1] ^= $this->pass($n[0] + $this->k[7]);
        $n[0] ^= $this->pass($n[1] + $this->k[6]);
        $n[1] ^= $this->pass($n[0] + $this->k[5]);
        $n[0] ^= $this->pass($n[1] + $this->k[4]);
        $n[1] ^= $this->pass($n[0] + $this->k[3]);
        $n[0] ^= $this->pass($n[1] + $this->k[2]);
        $n[1] ^= $this->pass($n[0] + $this->k[1]);
        $n[0] ^= $this->pass($n[1] + $this->k[0]);

        $n[1] ^= $this->pass($n[0] + $this->k[7]);
        $n[0] ^= $this->pass($n[1] + $this->k[6]);
        $n[1] ^= $this->pass($n[0] + $this->k[5]);
        $n[0] ^= $this->pass($n[1] + $this->k[4]);  //3466386349
        $n[1] ^= $this->pass($n[0] + $this->k[3]);
        $n[0] ^= $this->pass($n[1] + $this->k[2]);
        $n[1] ^= $this->pass($n[0] + $this->k[1]);
        $n[0] ^= $this->pass($n[1] + $this->k[0]);

        $n[1] ^= $this->pass($n[0] + $this->k[7]);
        $n[0] ^= $this->pass($n[1] + $this->k[6]);
        $n[1] ^= $this->pass($n[0] + $this->k[5]);
        $n[0] ^= $this->pass($n[1] + $this->k[4]);
        $n[1] ^= $this->pass($n[0] + $this->k[3]);
        $n[0] ^= $this->pass($n[1] + $this->k[2]);
        $n[1] ^= $this->pass($n[0] + $this->k[1]);
        $n[0] ^= $this->pass($n[1] + $this->k[0]);

        $out = array();
        $out[0] = $n[1] & 0xff;
        $out[1] = Util::rrr($n[1], 8) & 0xff;
        $out[2] = Util::rrr($n[1], 16) & 0xff;
        $out[3] = Util::rrr($n[1], 24);
        $out[4] = $n[0] & 0xff;
        $out[5] = Util::rrr($n[0], 8) & 0xff;
        $out[6] = Util::rrr($n[0], 16) & 0xff;
        $out[7] = Util::rrr($n[0], 24);
        return $out;     //216 205 110 128 165 137 175 83
    }

    public function decrypt_cfb($iv, $data) {
        $this->gamma = Util::alloc(8);
        $cur_iv = Util::alloc(8);

        for ($idx = 0; $idx < 8; $idx++) {
            $cur_iv[$idx] = $iv[$idx];
        }

        $blocks = ceil(count($data) / 8);
        $clear = Util::alloc($blocks * 8);

        $idx = 0;
        $off = 0;
        while ($idx < $blocks) {
            $off = $idx++ * 8;
            $res = $this->decrypt64_cfb($cur_iv, array_slice($data, $off, 8));
            $cur_iv = $res[1];
            for ($i = 0; $i < 8; $i++) {
                $clear[$off + $i] = $res[0][$i];
            }
        }


        return $clear;
    }

    public function decrypt64_cfb($iv, $data) {

        $clear = Util::alloc(8);
        $this->gamma = $this->crypt64($iv);


        for ($j = 0; $j < 8; $j++) {
            if(!isset($data[$j])) {
                $data[$j] =0;
            }
            $iv[$j] = $data[$j];
            $clear[$j] = $data[$j] ^ $this->gamma[$j];
        }

        return array($clear, $iv);
    }

}

class SBox
{
    public $k1 = array();
    public $k2 = array();
    public $k3 = array();
    public $k4 = array();
    public $k5 = array();
    public $k6 = array();
    public $k7 = array();
    public $k8 = array();

    public function __construct() {

        $default = '0102030E060D0B080F0A0C050709000403080B0506040E0A020C0107090F0D0002080907050F000B0C010D0E0A0306040F080E090702000D0C0601050B04030A03080D09060B0F0002050C0A040E01070F0605080E0B0A040C0003070209010D08000C040906070B0203010F050E0A0D0A090D060E0B04050F01030C07000802';

        $a = Util::hex2array($default);

        $this->k8 = array_slice($a, 0, 16);
        $this->k7 = array_slice($a, 16, 16);
        $this->k6 = array_slice($a, 32, 16);
        $this->k5 = array_slice($a, 48, 16);
        $this->k4 = array_slice($a, 64, 16);
        $this->k3 = array_slice($a, 80, 16);
        $this->k2 = array_slice($a, 96, 16);
        $this->k1 = array_slice($a, 112, 16);
    }

}
