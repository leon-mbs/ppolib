<?php
  
namespace PPOLib;

use PPOLib\Util;

class Curve
{
    public $m;
    public $ks;
    public $a;
    public $b;
    public $order;
    public $kofactor;
    public $base;

    public function __construct($cpar, $le = false) {
        $this->ks = array();

        if($cpar->isType(\Sop\ASN1\Type\Primitive\ObjectIdentifier::TYPE_OBJECT_IDENTIFIER)) {
            $oid = $cpar->asObjectIdentifier()->oid();
            if($oid =="1.2.804.2.1.1.1.1.3.1.1.2.9") { //DSTU_PB_431
                $this->a = 1;
                $this->b = Field::fromString("03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66BAC536B18AE2DC312CA493117DAA469C640CAF3", 16, $this);
                $this->order = Field::fromString("3FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBA3175458009A8C0A724F02F81AA8A1FCBAF80D90C7A95110504CF", 16, $this);
                $x = Field::fromString("1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49A2A95058068426C2171E99FD3B43C5947C857D", 16, $this);
                $y = Field::fromString("70B5E1E14031C1F70BBEFE96BDDE66F451754B4CA5F48DA241F331AA396B8D1839A855C1769B1EA14BA53308B5E2723724E090E02DB9", 16, $this);
                $this->base =    new Point($x, $y);

                $this->m = 431;
                $this->ks[] = 1;
                $this->ks[] = 3;
                $this->ks[] = 5;
                $this->kofactor = [4];

            }
            if($oid =="1.2.804.2.1.1.1.1.3.1.1.2.6") { //DSTU_PB_257
                $this->a = 0;
                $this->b = Field::fromString("01CEF494720115657E18F938D7A7942394FF9425C1458C57861F9EEA6ADBE3BE10", 16, $this);
                $this->order = Field::fromString("800000000000000000000000000000006759213AF182E987D3E17714907D470D", 16, $this);
                $x = Field::fromString("2A29EF207D0E9B6C55CD260B306C7E007AC491CA1B10C62334A9E8DCD8D20FB7", 16, $this);
                $y = Field::fromString("010686D41FF744D4449FCCF6D8EEA03102E6812C93A9D60B978B702CF156D814EF", 16, $this);
                $this->base =    new Point($x, $y);

                $this->m = 257;
                $this->ks[] = 12;

                $this->kofactor = [4];

            }

            return;
        }

        if($cpar->isType(\Sop\ASN1\Type\Constructed\Sequence::TYPE_SEQUENCE)) {
            $seq = $cpar->asSequence();
        }


        $this->a = $seq->at(1)->asInteger()->number();
        $b = $seq->at(2)->asOctetString()->string();
        $a = Util::bstr2array($b);
        if ($le) {
            $a = array_reverse($a);
        }
        $ha = Util::array2hex($a);
        $this->b = Field::fromString($ha, 16, $this);

        $order = $seq->at(3)->asInteger()->number();
        $this->order = Field::fromString($order, 10, $this);
        $this->kofactor = [2];

        $this->m = $seq->at(0)->asSequence()->at(0)->asInteger()->number();


        $ksseq = $seq->at(0)->asSequence()->at(1);
        $type = $ksseq->tag();
        if ($type == 2) {   // trinominal
            $this->ks[] = $ksseq->asInteger()->number();
        }

        if ($type == 16) {   //pentanominal
            $this->ks[] = $ksseq->asSequence()->at(0)->asInteger()->number();
            $this->ks[] = $ksseq->asSequence()->at(1)->asInteger()->number();
            $this->ks[] = $ksseq->asSequence()->at(2)->asInteger()->number();
        }

        $base = $seq->at(4)->asOctetString()->string();
        $a = Util::bstr2array($base);
        if ($le) {
            $a = array_reverse($a);
        }
        $ha = Util::array2hex($a);
        $base = Field::fromString($ha, 16, $this);

        $le_b = $this->b->toString(16);
        $le_base = $base->toString(16);
        $le_order = $this->order->toString(16);

        $this->base = $this->expand($base);
    }

    public function expand($x) {

        //   $a = Field::fromString("".$this->a,10,$this) ;
        $hx = $x->toString(16);
        $bit = $x->testBit(0);
        $x->setBit(0, 0);

        $trace = $x->trace();
        if ((1 == (int) $trace && 0 == (int) $this->a) || (0 == (int) $trace && 1 == (int) $this->a)) {
            $x->setBit(0, 1);
        }
        $x2 = $x->mulmod($x);
        $y = $x2->mulmod($x);
        $y1 = $y->toString(16);

        if (1 == (int) $this->a) {
            $y = $y->add($x2);
        }
        $y2 = $y->toString(16);

        $y = $y->add($this->b);
        $y3 = $y->toString(16);

        $x2inv = $x2->invert();

        $hx2inv = $x2inv->toString(16);

        $y = $y->mulmod($x2inv);
        $y4 = $y->toString(16);

        $y = $this->fsquad($y);
        $y5 = $y->toString(16);


        $trace = $y->trace();
        if ((0 == (int) $trace && 1 == (int) $bit) || (1 == (int) $trace && 0 == (int) $bit)) {
            $bit = $y->testBit(0);
            $y->setBit(0, 1 ^ $bit);
        }

        $hx = $x->toString(16);
        $hy = $y->toString(16);
        $y6 = $y->toString(16);

        $y = $y->mulmod($x);
        $x->curve = $this;
        $y->curve = $this;

        $y7 = $y->toString(16);

        $xx2 = $x->toString(16);
        $yy2 = $y->toString(16);



        return new Point($x, $y);
    }

    public function fsquad(Field $v) {
        $mod = $this->getModulo();

        $hv = $v->toString(16);
        $bitl_m = $this->m;
        $range_to = ($bitl_m - 1) / 2;
        $val_a = $v->mod();

        $val_z = $val_a->clone();
        ;

        for ($idx = 1; $idx <= $range_to; $idx += 1) {

            $val_z = $val_z->mulmod($val_z);
            $val_z = $val_z->mulmod($val_z);

            $val_z = $val_z->add($val_a);
        }

        $val_w = $val_z->mulmod($val_z);
        $val_w = $val_w->add($val_z);

        if ($val_w->compare($val_a) == 0) {
            return $val_z->mod();
        }

        throw new \Exception("squad eq fail");
    }

    public function getModulo() {

        $m = Field::get0($this);
        $m->setBit($this->m, 1);
        $m->setBit(0, 1);
        foreach ($this->ks as $v) {
            $m->setBit($v, 1);
        }

        return $m;
    }

    public function random() {

        $r = new Field();

        $r->value = gmp_init(rand(10, PHP_INT_MAX-1), 10);
        $r->curve = $this;
        $r = $this->truncate($r);

        return $r;
    }

    public function truncate($value) {
        $bitl_o = $this->order->getLength();

        $xbit = $value->getLength();
        $ret = $value->clone();
        $ret2 = $value->clone();
        while ($bitl_o <= $xbit) {
            $ret->setBit($xbit - 1, 0);
            $xbit = $ret->getLength();
        }

        return $ret->clone();
    }

}
