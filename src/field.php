<?php

namespace PPOLib;

class Field
{
    public $curve = null;
    public $value = null;

    public static function fromString($str, $base, $curve = null) {

        $f = new Field();
        $f->value = gmp_init($str, $base);

        $f->curve = $curve;

        return $f;
    }

    public static function fromInt($v, $curve = null) {

        $f = new Field();
        $f->value = gmp_init((int) $v);

        $f->curve = $curve;
        return $f;
    }

    public static function fromBinary($v, $curve = null) {
        $v = Util::array2hex(Util::bstr2array($v));
        $f = new Field();
        $f->value = gmp_init($v, 16);

        $f->curve = $curve;
        return $f;
    }

    public function toString($base = 10) {
        return gmp_strval($this->value, $base);
    }

    public function compare(Field $v) {

        return gmp_cmp($this->value, $v->value);
    }



    public function clone() {

        return Field::fromString($this->toString(16), 16, $this->curve);
    }

    public function getLength() {
        return strlen(gmp_strval($this->value, 2));
    }

    public function testBit($i) {
        return gmp_testbit($this->value, $i) == true ? 1 : 0;
        ;
    }

    public function setBit($i, $v) {
        gmp_setbit($this->value, $i, $v);
    }

    public function shiftLeft($n) {

        $value = gmp_mul($this->value, gmp_pow(2, $n)) ;

        $f = new Field();
        $f->value = $value;


        $f->curve = $this->curve;

        return $f;

    }

    public function shiftRight($n) {

        //(gmp_div($x,gmp_pow(2,$n)));

        $s = gmp_strval($this->value, 2);
        $s = substr($s, 0, strlen($s)-$n) ;

        //  $s0 = str_repeat('0', $n);
        //  $s = $s . $s0;
        $f = new Field();
        $f->curve = $this->curve;
        $f->value = gmp_init($s, 2);

        return $f;

    }

    public function shiftRightCycle($n) {
        $s = gmp_strval($this->value, 2);
        ;
        for ($i = 0; $i < n; $i++) {
            $last = substr($s, strlen($s) - 1, 1);
            $s = $last . substr($s, 0, strlen($s) - 1);
        }
        $f = new Field();
        $f->value = gmp_init($s, 2);
        $f->curve = $this->curve;
        if ($f->curve == null) {
            $f->curve = $v->curve;
        }
        return $f;
    }

    public function trace() {
        $m = $this->curve->m;
        $t = $this->clone();
        // $h = $t->toString(16);
        for ($i = 1; $i <= $m - 1; $i++) {
            $t = $t->mulmod($t);
            //   $h1 = $t->toString(16);
            $t = $t->add($this);
            //  $h2 = $t->toString(16);
        }
        //  $h = $t->toString(16);
        return $t->testBit(0);
    }

    public function add(Field $v) {

        $f = new Field();
        $f->value = gmp_xor($this->value, $v->value);
        $f->curve = $this->curve;
        if ($f->curve == null) {
            $f->curve = $v->curve;
        }
        return $f;
    }



    public static function get0($curve = null) {

        $f = new Field();
        $f->value = gmp_init((int) 0);

        $f->curve = $curve;
        return $f;
    }

    public static function get1($curve = null) {

        $f = new Field();
        $f->value = gmp_init((int) 1);

        $f->curve = $curve;
        return $f;
    }

    public function is0() {

        $s = $this->toString(2);

        return $s == '0';
    }

    public function powmod($t) {
        if ($t == 0) {
            return Field::get1();
        }
        if ($t == 1) {
            return $this->clone();
        }
        $x = $this->clone();
        for ($i = $t; $i > 1; $i--) {
            $x = $x->mulmod($x);
        }

        return $x;
    }

    public function mod() {

        $m = $this->curve->getModulo();
        $cmp = $this->compare($m);
        if ($cmp == 0) {
            return Field::get0();
        }
        if ($cmp < 0) {
            return $this->clone();
        }

        $rc = $this->div($m);

        return $rc[1];
    }

    public function mulmod(Field $v) {
        $m = $this->mul($v);
        $r = $m->mod();
        return $r;
    }

    public function divmod(Field $v) {
        // $m = $this->div($v) ;
        //   $r = $m->mod()  ;
        //  return $r;
    }

    public function mul(Field $v) {

        $bag = Field::get0();
        $shift = $this->clone();

        for ($i = 0; $i < $v->getLength(); $i++) {

            //  $bh = $bag->toString(2) ;


            $bit = $v->testBit($i);
            if ($bit == 1) {
                $bag = $bag->add($shift);
            }
            //   $bh2 = $bag->toString(2) ;
            $shift = $shift->shiftLeft(1);
        }
        $bag->curve = $this->curve;
        if ($bag->curve == null) {
            $bag->curve = $v->curve;
        }

        return $bag;
    }

    public function div(Field $v) {
        $res = '';

        $c = $this->compare($v);
        if ($c == 0) {
            return array(Field::get1(), Field::get0());
        }
        if ($c < 0) {
            return array(Field::get0(), $this->clone());
        }
        $bag = $this->clone();
        $vl = $v->getLength();

        while (true) {
            $bl = $bag->getLength();
            $shift = $v->clone();
            $shift = $shift->shiftLeft($bl - $vl);

            $bag = $bag->add($shift);
            $fh = $bag->toString(2);
            $res .= "1";
            $blnew = $bag->getLength();
            $bdiff = $bl - $blnew;
            if ($blnew < $vl) {

                $ediff = $bl - $vl;  //осталось  до  конца
                if ($ediff > 0) {
                    $res = $res . str_repeat('0', $ediff);
                }
                $rest = $bag;
                $rh = $rest->toString(2);

                $rs = Field::fromString($res, 2);
                $rsh = $rs->toString(2);
                return array($rs, $rest);
            }
            if ($bdiff > 1) {
                $res = $res . str_repeat('0', $bdiff - 1);
            }
        }
    }

    public function invert() {


        $r = $this->mod();
        $s = $this->curve->getModulo();
        ;

        $u = Field::get1($this->curve);
        $v = Field::get0($this->curve);

        while ($r->getLength() > 1) {
            $j = $s->getLength() - $r->getLength();

            if ($j < 0) {

                $tmp = $r->clone();
                $r = $s->clone();
                $s = $tmp;
                $tmp = $u->clone();
                $u = $v->clone();
                $v = $tmp;
                $j = 0 - $j;
            }


            $s = $s->add($r->shiftLeft($j));
            $v = $v->add($u->shiftLeft($j));

            $hu = $u->toString(16);
            $rh = $r->toString(16);
        }

        return $u;
    }


}
