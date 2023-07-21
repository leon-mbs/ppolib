<?php

namespace PPOLib\Algo;

use PPOLib\Util;

// хеширование
class Hash
{
    private $left = array();
    private $len = 0;
    private $U = array();
    private $W = array();
    private $V = array();
    private $_S = array();
    private $Key = array();
    private $c8buf = array();
    private $H = array();
    private $S = array();
    private $buf = array();
    private $ab2 = array();

    public function __construct() {

        $this->H = Util::alloc(32);
        $this->buf = Util::alloc(32);
        $this->S = Util::alloc(32);
        $this->_S = Util::alloc(32);
        $this->ab2 = Util::alloc(4);
    }

    private function _n($b) {
        if (is_array($b)) {
            $a = array();
            foreach ($b as $e) {
                if ($e < 0) {
                    $a[] = 256 + $e;
                } else {
                    $a[] = $e;
                }
            }

            return $a;
        }


        if ($b < 0) {
            return 256 + $b;
        } else {
            return $b;
        }
    }

    public function update($block) {
        $block = array_merge($this->left, $block);
        $block32 = array();
        for ($i = 0; $i < count($block); $i++) {
            $block32[$i] = $block[$i];
        }
        $off = 0;
        while (count($block) - $off >= 32) {
            $this->H = $this->step($this->H, $block32);
            $this->S = $this->add_blocks(32, $this->S, $block32);
            $off += 32;
            $block32 = array_slice($block, $off, 32);
        }
        $this->len += $off;

        if (count($block32) > 0) {
            $this->left = $block32;
        }


        //$off = 0;
    }

    public function finish() {
        $ret = array();
        $buf = $this->buf;
        $fin_len = $this->len;

        if (count($this->left) > 0) {
            for ($idx = 0; $idx < count($this->left); $idx++) {
                $buf[$idx] = $this->left[$idx];
            }
            $this->H = $this->step($this->H, $buf);
            $this->S = $this->add_blocks(32, $this->S, $buf);
            $fin_len += count($this->left);
            $this->left = array();

            for ($idx = 0; $idx < 32; $idx++) {
                $buf[$idx] = 0;
            }
        }
        $fin_len <<= 3;
        $idx = 0;
        while ($fin_len > 0) {
            $buf[$idx++] = $fin_len & 0xff;
            $fin_len >>= 8;
        }

        $this->H = $this->step($this->H, $buf);
        $this->H = $this->step($this->H, $this->S);

        for ($idx = 0; $idx < 32; $idx++) {
            $ret[$idx] = $this->H[$idx];
        }
        $fin_len <<= 3;

        return $ret;
    }

    public static function gosthash($data) {
        if (is_string($data)) {
            $data = Util::str2array($data);
        }

        $hash = new Hash();
        $hash->update($data);

        $ret = $hash->finish();

        return $ret;
    }

    public function update32($block32) {


        $this->H = $this->step($this->H, $block32);

        $this->S = $this->add_blocks(32, $this->S, $block32);
        $this->len += 32;

    }

    private static function xor_blocks($a, $b) {
        $ret = array();
        for ($i = 0; $i < count($a); $i++) {
            $ret[$i] = $a[$i] ^ $b[$i];
        }
        return $ret;
    }

    private static function swap_bytes($w) {
        $k = Util::alloc(count($w));
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 8; $j++) {
                $k[$i + 4 * $j] = $w[8 * $i + $j];
            }
        }
        return $k;
    }

    private static function circle_xor8($w, $k) {
        $c8buf = Util::alloc(8);
        for ($i = 0; $i < 8; $i++) {
            $c8buf[$i] = $w[$i];
        }
        for ($i = 0; $i < 24; $i++) {
            $k[$i] = $w[$i + 8];
        }
        for ($i = 0; $i < 8; $i++) {
            $k[$i + 24] = $c8buf[$i] ^ $k[$i];
        }
        return $k;
    }

    private static function transform_3($data) {

        $t16 = ($data[0] ^ $data[2] ^ $data[4] ^ $data[6] ^ $data[24] ^ $data[30]) |
                (($data[1] ^ $data[3] ^ $data[5] ^ $data[7] ^ $data[25] ^ $data[31]) << 8);

        //  for ($i = 0; $i < 30; $i++) {
        //      $data[$i] = $data[$i + 2];
        //   }   //optimize

        $data = array_slice($data, 2);
        $data[30] = $t16 & 0xff;
        $data[31] = Util::rrr($t16, 8);
        return $data;
    }

    private function step($H, $M) {



        $U = Util::alloc(32);
        $V = Util::alloc(32);
        $S = $this->_S;

        $W = Hash::xor_blocks($H, $M);
        $Key = Hash::swap_bytes($W);

        $gost = new Gost();
        $gost->key($Key);
        $_S = $gost->crypt64($H);
        for ($i = 0; $i < 8; $i++) {
            $S[$i] = $_S[$i];
        }

        $U = Hash::circle_xor8($H, $U);
        $V = Hash::circle_xor8($M, $V);
        $V = Hash::circle_xor8($V, $V);
        $W = Hash::xor_blocks($U, $V);
        $Key = Hash::swap_bytes($W);



        $gost->key($Key);
        $_S = $gost->crypt64(array_slice($H, 8, 8));
        for ($i = 0; $i < 8; $i++) {
            $S[$i + 8] = $_S[$i];
        }

        $U = Hash::circle_xor8($U, $U);
        $U[31] = ~$U[31];
        $U[29] = ~$U[29];
        $U[28] = ~$U[28];
        $U[24] = ~$U[24];
        $U[23] = ~$U[23];
        $U[20] = ~$U[20];
        $U[18] = ~$U[18];
        $U[17] = ~$U[17];
        $U[14] = ~$U[14];
        $U[12] = ~$U[12];
        $U[10] = ~$U[10];
        $U[8] = ~$U[8];
        $U[7] = ~$U[7];
        $U[5] = ~$U[5];
        $U[3] = ~$U[3];
        $U[1] = ~$U[1];

        $U = $this->_n($U);

        $V = Hash::circle_xor8($V, $V);
        $V = Hash::circle_xor8($V, $V);
        $W = Hash::xor_blocks($U, $V);
        $Key = Hash::swap_bytes($W);
        $gost->key($Key);
        $_S = $gost->crypt64(array_slice($H, 16, 8));
        for ($i = 0; $i < 8; $i++) {
            $S[$i + 16] = $_S[$i];
        }
        $U = Hash::circle_xor8($U, $U);
        $V = Hash::circle_xor8($V, $V);
        $V = Hash::circle_xor8($V, $V);
        $W = Hash::xor_blocks($U, $V);
        $Key = Hash::swap_bytes($W);
        $gost->key($Key);
        $_S = $gost->crypt64(array_slice($H, 24, 8));
        for ($i = 0; $i < 8; $i++) {
            $S[$i + 24] = $_S[$i];
        }
        for ($i = 0; $i < 12; $i++) {
            $S = Hash::transform_3($S);
        }
        $_S = Hash::xor_blocks($S, $M);
        for ($i = 0; $i < count($_S); $i++) {
            $S[$i] = $_S[$i];
        }

        $S = Hash::transform_3($S);

        $_S = Hash::xor_blocks($S, $H);
        for ($i = 0; $i < count($_S); $i++) {
            $S[$i] = $_S[$i];
        }

        for ($i = 0; $i < 61; $i++) {
            $S = Hash::transform_3($S);
        }
        for ($i = 0; $i < 32; $i++) {
            $H[$i] = $S[$i];
        }
        $this->Key = $Key;
        $this->_S = $S;

        return $H;
    }

    private function add_blocks($n, $left, $right) {

        $this->ab2[2] = 0;
        $this->ab2[3] = 0;

        for ($i = 0; $i < $n; $i++) {
            $this->ab2[0] = $left[$i];
            $this->ab2[1] = $right[$i];
            $this->ab2[2] = $this->ab2[0] + $this->ab2[1] + $this->ab2[3];
            $left[$i] = $this->ab2[2] & 0xff;
            $this->ab2[3] = Util::rrr($this->ab2[2], 8);
        }

        // return $this->ab2[3];
        return $left;
    }

}
