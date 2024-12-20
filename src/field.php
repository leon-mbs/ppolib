<?php

namespace PPOLib;

class Field
{
    public $curve = null;
    public $value = null;

    public static function fromString($str, $base, $curve = null){
        $f = new Field();
        $f->value = gmp_init($str, $base);
        $f->curve = $curve;
        return $f;
    }

    public static function fromInt($v, $curve = null){
        $f = new Field();
        $f->value = gmp_init((int)$v);
        $f->curve = $curve;
        return $f;
    }

    public static function fromBinary($v, $curve = null){
        $v = Util::array2hex(Util::bstr2array($v));
        $f = new Field();
        $f->value = gmp_init($v, 16);
        $f->curve = $curve;
        return $f;
    }

    public function toString($base = 10){
        return gmp_strval($this->value, $base);
    }

    public function compare(Field $v){
        return gmp_cmp($this->value, $v->value);
    }

    public function clone(){
        return Field::fromString($this->toString(16), 16, $this->curve);
    }

    public function getLength(){
        return strlen(gmp_strval($this->value, 2));
    }

    public function testBit($i){
        return gmp_testbit($this->value, $i) ? 1 : 0;
    }

    public function setBit($i, $v){
        gmp_setbit($this->value, (int)$i, $v == 1);
    }

   
    public function shiftLeft($n){
        if ($n < 0) {
            throw new \InvalidArgumentException("Shift amount cannot be negative.");
        }

        $value = $this->value;
        while ($n > 0) {
            $step = min($n, 32); //  используем меньшие  шаги для  сдвига
            $value = gmp_mul($value, gmp_pow(2, $step));
            $n -= $step;
        }

        $f = new Field();
        $f->value = $value;
        $f->curve = $this->curve;
        return $f;
    }

 
    public function shiftRight($n){
        if ($n < 0) {
            throw new \InvalidArgumentException("Shift amount cannot be negative.");
        }

        $value = $this->value;
        while ($n > 0) {
            $step = min($n, 32); // используем меньшие  шаги для  сдвига
            $value = gmp_div_q($value, gmp_pow(2, $step));
            $n -= $step;
        }

        $f = new Field();
        $f->value = $value;
        $f->curve = $this->curve;
        return $f;
    }

    public function shiftRightCycle($n){
        $s = gmp_strval($this->value, 2);
        for ($i = 0; $i < $n; $i++) {
            $last = substr($s, -1);
            $s = $last . substr($s, 0, -1);
        }
        $f = new Field();
        $f->value = gmp_init($s, 2);
        $f->curve = $this->curve;
        return $f;
    }

    public function trace(){
        $m = $this->curve->m;
        $t = $this->clone();
        for ($i = 1; $i < $m; $i++) {
            $t = $t->mulmod($t)->add($this);
        }
        return $t->testBit(0);
    }

    public function add(Field $v){
        $f = new Field();
        $f->value = gmp_xor($this->value, $v->value);
        $f->curve = $this->curve ?: $v->curve;
        return $f;
    }

    public static function get0($curve = null){
        $f = new Field();
        $f->value = gmp_init(0);
        $f->curve = $curve;
        return $f;
    }

    public static function get1($curve = null){
        $f = new Field();
        $f->value = gmp_init(1);
        $f->curve = $curve;
        return $f;
    }

    public function is0(){
        return $this->toString(2) == '0';
    }

    public function powmod($t){
        if ($t < 0) {
            throw new \InvalidArgumentException("Exponent cannot be negative.");
        }

        if ($t == 0) {
            return Field::get1();
        }

        if ($t == 1) {
            return $this->clone();
        }

        $x = $this->clone();
        for ($i = 1; $i < $t; $i++) {
            $x = $x->mulmod($x);
        }
        return $x;
    }

    public function mod(){
        $m = $this->curve->getModulo();

 
        $cmp = $this->compare($m);
        if ($cmp == 0) {
            return Field::get0();
        }
        if ($cmp < 0) {
            return $this->clone();
        }
        return $this->div($m)[1];
    }

    public function mulmod(Field $v){
        $m = $this->mul($v);
        return $m->mod();
    }

    public function divmod(Field $v){
        // Implement if needed
    }

    public function mul(Field $v){
        $bag = Field::get0();
        $shift = $this->clone();
        for ($i = 0; $i < $v->getLength(); $i++) {
            if ($v->testBit($i) == 1) {
                $bag = $bag->add($shift);
            }
            $shift = $shift->shiftLeft(1);
        }
        $bag->curve = $this->curve ?: $v->curve;
        return $bag;
    }

    public function div(Field $v){
        $res = '';
        $c = $this->compare($v);
        if ($c == 0) {
            return [Field::get1(), Field::get0()];
        }
        if ($c < 0) {
            return [Field::get0(), $this->clone()];
        }
        $bag = $this->clone();
        $vl = $v->getLength();
        while (true) {
            $bl = $bag->getLength();
            $shift = $v->clone()->shiftLeft($bl - $vl);
            $bag = $bag->add($shift);
            $res .= "1";
            $blnew = $bag->getLength();
            $bdiff = $bl - $blnew;
            if ($blnew < $vl) {
                $res .= str_repeat('0', $bl - $vl);
                return [Field::fromString($res, 2), $bag];
            }
            if ($bdiff > 1) {
                $res .= str_repeat('0', $bdiff - 1);
            }
        }
    }

    public function invert(){
        $r = $this->mod();
        $s = $this->curve->getModulo();
        $u = Field::get1($this->curve);
        $v = Field::get0($this->curve);
        while ($r->getLength() > 1) {
            $j = $s->getLength() - $r->getLength();
            if ($j < 0) {
                [$r, $s] = [$s, $r];
                [$u, $v] = [$v, $u];
                $j = -$j;
            }
            $s = $s->add($r->shiftLeft($j));
            $v = $v->add($u->shiftLeft($j));
        }
        return $u;
    } 
    
    public function buf8(){
        $s=  $this->toString(16)  ;
      
        $a2= str_split($s,2) ;
        $buf=[];
        foreach($a2 as $i) {
           $buf[]= hexdec($i) ;  
        }      
       
        return $buf;
    }
    
}
