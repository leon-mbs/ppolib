<?php

namespace PPOLib;

use PPOLib\Util;

/**
* точка  на  эллиптической  кривой
*/
class Point
{
    public $x;
    public $y;

    public function __construct($x, $y) {

        $this->x = $x;
        $this->y = $y;
    }

    public function add(Point $p) {


        $a = Field::fromInt($this->x->curve->a ??0, $this->x->curve);
        $pz = new Point(Field::get0($this), Field::get0($this));

        $x0 = $this->x->clone();
        ;
        $y0 = $this->y->clone();
        ;
        $x1 = $p->x->clone();
        ;
        $y1 = $p->y->clone();
        ;

        if ($this->iszero()) {
            return $p;
        }

        if ($p->iszero()) {
            return $this;
        }

        if ($x0->compare($x1) != 0) {
            $tmp = $y0->add($y1);
            $tmp2 = $x0->add($x1);
            $lbd = $tmp->mulmod($tmp2->invert());
            $x2 = $a->add($lbd->mulmod($lbd));
            $x2 = $x2->add($lbd);
            $x2 = $x2->add($x0);
            $x2 = $x2->add($x1);
        } else {
            if ($y1->compare($y0) != 0) {
                return $pz;
            }
            if ($x1->compare(Field::get0()) == 0) {
                return $pz;
            }

            $lbd = $x1->add($p->y->mulmod($p->x->invert()));
            $x2 = $lbd->mulmod($lbd)->add($a);
            $x2 = $x2->add($lbd);
        }

        $y2 = $lbd->mulmod($x1->add($x2));
        $y2 = $y2->add($x2);
        $y2 = $y2->add($y1);

        $pz->x = $x2->clone();
        $pz->y = $y2->clone();

        return $pz;
    }

    public function mul(Field $f) {
        $pz = new Point(Field::get0($f->curve), Field::get0($f->curve));

        $p = $this->clone();
        //$hx = $p->x->toString(16);
        //   $hy = $p->y->toString(16);

        for ($j = $f->getLength() - 1; $j >= 0; $j--) {
            if ($f->testBit($j) == 1) {
                $pz = $pz->add($p);
                $p = $p->add($p);
            } else {
                $p = $pz->add($p);
                $pz = $pz->add($pz);
            }
        }


        return $pz;
    }

    public function negate() {
        return new Point($this->x, $this->x->add($this->y));
    }

    public function clone() {
        return new Point($this->x, $this->y);
    }

    public function isequal($p) {
        return ($this->x->compare($p->x) == 0) && ($this->y->compare($p->y) == 0);
    }

    public function iszero() {

        return ($this->x->is0()) && ($this->y->is0());
    }
   
    public function compress() {
        
        $x_inv = $this->x->invert();
        $tmp = $x_inv->mulmod($this->y);
        $trace = $tmp->trace();
        if ($trace === 1) {
           $this->x->setBit(0,1);
        }  else {
           $this->x->setBit(0,0);
        }
        return $this->x;
    }
}