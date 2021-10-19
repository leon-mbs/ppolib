<?php
  
 
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
 
 
 class  Curve {
                    
   public $m,$ks,$a, $b,$order,$kofactor,$base;
                  
                  
   public function __construct($seq,$le=false) {
              
           $this->a = $seq->at(1)->asInteger()->number();
           $b = $seq->at(2)->asOctetString()->string();
           $a = Util::bstr2array($b) ;
           if($le){
              $a = array_reverse($a) ;   
           }
           $ha = Util::array2hex($a) ;  
           $this->b  = Field::fromString($ha,16,$this )  ;
           
           $order  = $seq->at(3)->asInteger()->number() ;
           $this->order = Field::fromString($order,10,$this) ;
           $this->kofactor = [2];
             
           $this->m =  $seq->at(0)->asSequence()->at(0)->asInteger()->number() ;
      
           $this->ks=array();
          
           $ksseq = $seq->at(0)->asSequence()->at(1)  ;
           $type = $ksseq->tag();
           if($type == 2){   // trinominal
               $this->ks[] = $ksseq->asInteger()->number();
           }
           
           if($type == 16){   //pentanominal
                
                $this->ks[] =  $ksseq->asSequence()->at(0)->asInteger()->number();
                $this->ks[] =  $ksseq->asSequence()->at(1)->asInteger()->number() ;
                $this->ks[] =  $ksseq->asSequence()->at(2)->asInteger()->number() ;
            
           }
     
           $base =  $seq->at(4)->asOctetString()->string();
           $a = Util::bstr2array($base) ;
          if($le){
            $a = array_reverse($a) ;     
          } 
           $ha = Util::array2hex($a) ;  
           $base  = Field::fromString($ha,16,$this)  ;
           
           $le_b =  $this->b->toString(16);
           $le_base =  $base->toString(16);
           $le_order =   $this->order->toString(16);
           
           
  //"2a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb6"
  
  //"4440441545504001551005441451450111150510414004505001450155400001544501041015044014501005014040505104441544051505140510400554514"
        // $mm =   $base->mul($base) ;
        // $h = $mm->toString(16) ;
        // $dd =  $mm->div($base)  ;
        // $hw = $dd[0]->toString(16) ;
       
         $this->base = $this->expand($base) ;
    
      
   }
    public   function expand($x ){
         
       //   $a = Field::fromString("".$this->a,10,$this) ;
        $hx = $x->toString(16) ;    
          $bit = $x->testBit(0) ;
          $x->setBit(0,0) ;
         
          $trace = $x->trace();
          if( (1==(int)$trace  && 0==(int)$this->a)||(0==(int)$trace  && 1==(int)$this->a)) {
              $x->setBit(0,1) ;   
          }
          $x2 = $x->mulmod($x)  ;
          $y = $x2->mulmod($x);
 $hyiee = $y->toString(16) ;            
          if(1==(int)$this->a) {
             $y = $y->add($x2); 
          }
    $hyieww = $y->toString(16) ;       
    $hyiewwb = $x2->toString(16) ;       
          $y = $y->add($this->b); 
         $hyibbbb = $this->b->toString(16) ;  
         $hyi = $y->toString(16) ;  
          $x2inv=$x2->invert();
          $y = $y->mulmod($x2inv); 
          
          $hy1 = $y->toString(16) ; 
          $y = $this->fsquad($y);   
          $hy2 = $y->toString(16) ; 
          $trace = $y->trace();
          if( (0==(int)$trace  && 1==(int)$bit)||(1==(int)$trace  && 0==(int)$bit)) {
              $y->setBit(0,1) ;   
          }          
          
          $y = $y->mulmod($x);
          $h23 = $y->toString(16) ;    
          
          return  new Point($x,$y);
      }   
 
  public function fsquad(Field $v ) {
      $mod = $this->getModulo()  ;
      if ($mod->testbit(0)!=1) {
 
        throw new \Exception("only odd modulus is supported");
      }
    $hv = $v->toString(16) ;
  $bitl_m = $this->m;
  $range_to = ($bitl_m - 1) / 2;
  $val_a = $v->mod();

  $val_z = $val_a->clone();;
      
      
   for ($idx = 1; $idx <= $range_to; $idx += 1) {
       
    $val_z = $val_z->mulmod($val_z);
    $val_z = $val_z->mulmod($val_z);
    
    $val_z =  $val_z->add($val_a);
  }

  $val_w = $val_z->mulmod($val_z);
  $val_w = $val_w->add($val_z);

  if ($val_w->compare($val_a)==0) {
    return $val_z->mod();
  }

   throw new \Exception("squad eq fail");    
      
      
    
    }   
      public function getModulo(){
   
          $m = Field::get0($this) ;
          $m->setBit($this->m,1) ;
          $m->setBit(0,1) ;
          foreach($this->ks as $v) {
             $m->setBit($v,1) ;              
          }

          return $m;
          
      }
          
 }      
 
