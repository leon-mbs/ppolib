<?php

namespace PPOLib\Algo;

use PPOLib\Util;

class SHA1
{
    private $blocks = array();
    private $HEX_CHARS = array();
    private $SHIFT = array(24, 16, 8, 0);
    private $EXTRA = array(-2147483648, 8388608, 32768, 128);
    private $h0   ;
    private $h1  ;
    private $h2  ;
    private $h3  ;
    private $h4  ;
    private $block = 0;
    private $start = 0;
    private $bytes = 0;
    private $hBytes = 0;
    private $lastByteIndex = 0;
    private $finalized = false;
    private $hashed = false;
    private $first = true;

    public function __construct() {
        $this->blocks = Util::alloc(16);
        $this->HEX_CHARS = array('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f');
        $this->h0 = 0x67452301;
        $this->h1 = 0xEFCDAB89;
        // $this->h1 = Util::norm32($this->h1);

        $this->h2 = 0x98BADCFE;
        $this->h3 = 0x10325476;
        $this->h4 = 0xC3D2E1F0;
    }

    public function update($message) {
        if ($this->finalized) {
            return;
        }
        $code = $index = 0;

        $length = count($message);

        while ($index < $length) {


            if ($this->hashed) {
                $this->hashed = false;
                $this->blocks = Util::alloc(16);

                $this->blocks[0] = $this->block;
            }

            for ($i = $this->start; $index < $length && $i < 64; ++$index) {
                $this->blocks[$i >> 2] |= $message[$index] << $this->SHIFT[$i++ & 3];
            }


            $this->lastByteIndex = $i;

            $this->bytes += $i - $this->start;
            if ($i >= 64) {
                $this->block = $this->blocks[16];
                $this->start = $i - 64;
                $this->hash();
                $this->hashed = true;
            } else {
                $this->start = $i;
            }
        }
        if ($this->bytes > 4294967295) {
            $this->hBytes += $this->bytes / 4294967296 << 0;
            $this->bytes = $this->bytes % 4294967296;
        }
    }

    public function digest() {
        $this->finalize();
        $h0 = $this->h0;
        $h1 = $this->h1;
        $h2 = $this->h2;
        $h3 = $this->h3;
        $h4 = $this->h4;
        $ret = array(
            ($h0 >> 24) & 0xFF, ($h0 >> 16) & 0xFF, ($h0 >> 8) & 0xFF, $h0 & 0xFF,
            ($h1 >> 24) & 0xFF, ($h1 >> 16) & 0xFF, ($h1 >> 8) & 0xFF, $h1 & 0xFF,
            ($h2 >> 24) & 0xFF, ($h2 >> 16) & 0xFF, ($h2 >> 8) & 0xFF, $h2 & 0xFF,
            ($h3 >> 24) & 0xFF, ($h3 >> 16) & 0xFF, ($h3 >> 8) & 0xFF, $h3 & 0xFF,
            ($h4 >> 24) & 0xFF, ($h4 >> 16) & 0xFF, ($h4 >> 8) & 0xFF, $h4 & 0xFF
        );

        return $ret;
    }

    public function finalize() {
        if ($this->finalized) {
            return;
        }
        $this->finalized = true;
        $i = $this->lastByteIndex;
        $this->blocks[16] = $this->block;
        $this->blocks[$i >> 2] |= $this->EXTRA[$i & 3];
        $this->block = $this->blocks[16];
        if ($i >= 56) {
            if (!$this->hashed) {
                $this->hash();
            }
            $this->blocks = Util::alloc(16);
            $this->blocks[0] = $this->block;
        }
        $this->blocks[14] = $this->hBytes << 3 | Util::rrr($this->bytes, 29);
        $this->blocks[15] = $this->bytes << 3;
        $this->hash();
    }

    private function hash() {
        $a = $this->h0;
        $b = $this->h1;
        $c = $this->h2;
        $d = $this->h3;
        $e = $this->h4;
        $f=0;
        $j=0;
        $t=0;

        for ($j = 16; $j < 80; ++$j) {
            $t = $this->blocks[$j - 3] ^ $this->blocks[$j - 8] ^ $this->blocks[$j - 14] ^ $this->blocks[$j - 16];

            $this->blocks[$j] = Util::ll($t, 1) | (Util::rrr($t, 31));
        }


        for ($j = 0; $j < 20; $j += 5) {
            $f = Util::norm32(($b & $c) | ((~$b) & $d));
            $t = Util::norm32(Util::ll($a, 5) | (Util::rrr($a, 27)));
            $e = Util::norm32($t + $f + $e + 1518500249 + $this->blocks[$j] << 0);
            $b = Util::norm32(Util::ll($b, 30) | (Util::rrr($b, 2)));

            $f = Util::norm32(($a & $b) | ((~$a) & $c));


            $t =Util::norm32(Util::ll($e, 5) | (Util::rrr($e, 27)));
            $d = Util::norm32($t + $f + $d + 1518500249 + $this->blocks[$j + 1] << 0);
            $a = Util::norm32(Util::ll($a, 30) | (Util::rrr($a, 2)));

            $f = Util::norm32(($e & $a) | ((~$e) & $b));
            $t =Util::norm32(Util::ll($d, 5) | (Util::rrr($d, 27)));
            $c = Util::norm32($t + $f + $c + 1518500249 + $this->blocks[$j + 2] << 0);
            $e = Util::norm32(Util::ll($e, 30) | (Util::rrr($e, 2)));

            $f = Util::norm32(($d & $e) | ((~$d) & $a));
            $t =Util::norm32(Util::ll($c, 5) | (Util::rrr($c, 27)));
            $b = Util::norm32($t + $f + $b + 1518500249 + $this->blocks[$j + 3] << 0);
            $d = Util::norm32(Util::ll($d, 30) | (Util::rrr($d, 2)));

            $f =Util::norm32(($c & $d) | ((~$c) & $e));
            $t =Util::norm32(Util::ll($b, 5) | (Util::rrr($b, 27)));
            $a =Util::norm32($t + $f + $a + 1518500249 + $this->blocks[$j + 4] << 0);
            $c = Util::norm32(Util::ll($c, 30) | (Util::rrr($c, 2)));
        }

        for ($j ; $j < 40 ; $j += 5) {
            $f =Util::norm32($b ^ $c ^ $d);
            $t = Util::norm32(Util::ll($a, 5) | (Util::rrr($a, 27)));
            $e =Util::norm32($t + $f + $e + 1859775393 + $this->blocks[$j] << 0);
            $b =Util::norm32(Util::ll($b, 30) | (Util::rrr($b, 2)));

            $f = Util::norm32($a ^ $b ^ $c);
            $t = Util::norm32(Util::ll($e, 5) | (Util::rrr($e, 27)));
            $d = Util::norm32($t + $f + $d + 1859775393 + $this->blocks[$j + 1] << 0);
            $a = Util::norm32(Util::ll($a, 30) | (Util::rrr($a, 2)));

            $f = Util::norm32($e ^ $a ^ $b);
            $t = Util::norm32(Util::ll($d, 5) | (Util::rrr($d, 27)));
            $c = Util::norm32($t + $f + $c + 1859775393 + $this->blocks[$j + 2] << 0);
            $e = Util::norm32(Util::ll($e, 30) | (Util::rrr($e, 2)));

            $f = Util::norm32($d ^ $e ^ $a);
            $t = Util::norm32(Util::ll($c, 5) | (Util::rrr($c, 27)));
            $b = Util::norm32($t + $f + $b + 1859775393 + $this->blocks[$j + 3] << 0);
            $d = Util::norm32(Util::ll($d, 30) | (Util::rrr($d, 2)));

            $f = Util::norm32($c ^ $d ^ $e);
            $t = Util::norm32(Util::ll($b, 5) | (Util::rrr($b, 27)));

            $a = Util::norm32($t + $f + $a + 1859775393 + $this->blocks[$j + 4] << 0);
            $c = Util::norm32(Util::ll($c, 30) | (Util::rrr($c, 2)));
        }

        for ($j  ; $j < 60 ; $j += 5) {
            $f =Util::norm32(($b & $c) | ($b & $d) | ($c & $d));
            $t = Util::norm32(Util::ll($a, 5) | (Util::rrr($a, 27)));
            $e = Util::norm32($t + $f + $e - 1894007588 + $this->blocks[$j] << 0);
            $b = Util::norm32(Util::ll($b, 30) | (Util::rrr($b, 2)));

            $f = Util::norm32(($a & $b) | ($a & $c) | ($b & $c));
            $t =Util::norm32(Util::ll($e, 5) | (Util::rrr($e, 27)));
            $d =Util::norm32($t + $f + $d - 1894007588 + $this->blocks[$j + 1] << 0);
            $a = Util::norm32(Util::ll($a, 30) | (Util::rrr($a, 2)));

            $f =Util::norm32(($e & $a) | ($e & $b) | ($a & $b));
            $t = Util::norm32(Util::ll($d, 5) | (Util::rrr($d, 27)));
            $c =Util::norm32($t + $f + $c - 1894007588 + $this->blocks[$j + 2] << 0);
            $e = Util::norm32(Util::ll($e, 30) | (Util::rrr($e, 2)));

            $f =Util::norm32(($d & $e) | ($d & $a) | ($e & $a));
            $t =Util::norm32(Util::ll($c, 5) | (Util::rrr($c, 27)));
            $b =Util::norm32($t + $f + $b - 1894007588 + $this->blocks[$j + 3] << 0);
            $d =Util::norm32(Util::ll($d, 30) | (Util::rrr($d, 2)));

            $f =Util::norm32(($c & $d) | ($c & $e) | ($d & $e));
            $t = Util::norm32(Util::ll($b, 5) | (Util::rrr($b, 27)));
            $a = Util::norm32($t + $f + $a - 1894007588 + $this->blocks[$j + 4] << 0);
            $c = Util::norm32(Util::ll($c, 30) | (Util::rrr($c, 2)));
        }

        for ($j ; $j < 80 ; $j += 5) {
            $f = Util::norm32($b ^ $c ^ $d);
            $t =  Util::norm32(Util::ll($a, 5) | (Util::rrr($a, 27)));
            $e = Util::norm32($t + $f + $e - 899497514 + $this->blocks[$j] << 0);
            $b = Util::norm32(Util::ll($b, 30) | (Util::rrr($b, 2)));

            $f =  Util::norm32($a ^ $b ^ $c);
            $t = Util::norm32(Util::ll($e, 5) | (Util::rrr($e, 27)));
            $d =  Util::norm32($t + $f + $d - 899497514 + $this->blocks[$j + 1] << 0);
            $a =  Util::norm32(Util::ll($a, 30) | (Util::rrr($a, 2)));

            $f = Util::norm32($e ^ $a ^ $b);
            $t =  Util::norm32(Util::ll($d, 5) | (Util::rrr($d, 27)));
            $c = Util::norm32($t + $f + $c - 899497514 + $this->blocks[$j + 2] << 0);
            $e = Util::norm32(Util::ll($e, 30) | (Util::rrr($e, 2)));

            $f =  Util::norm32($d ^ $e ^ $a);
            $t = Util::norm32(Util::ll($c, 5) | (Util::rrr($c, 27)));
            $b =  Util::norm32($t + $f + $b - 899497514 + $this->blocks[$j + 3] << 0);
            $d =  Util::norm32(Util::ll($d, 30) | (Util::rrr($d, 2)));

            $f = Util::norm32($c ^ $d ^ $e);
            $t =  Util::norm32(Util::ll($b, 5) | (Util::rrr($b, 27)));
            $a =  Util::norm32($t + $f + $a - 899497514 + $this->blocks[$j + 4] << 0);
            $c = Util::norm32(Util::ll($c, 30) | (Util::rrr($c, 2)));
        }


        $this->h0 = $this->h0 + $a << 0;
        $this->h1 = $this->h1 + $b << 0;
        $this->h2 = $this->h2 + $c << 0;
        $this->h3 = $this->h3 + $d << 0;
        $this->h4 = $this->h4 + $e << 0;
    }

}
