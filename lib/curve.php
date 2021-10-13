<?php
  
 
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
 
 
 class  Curve {
                    
   public $m,$ks,$a, $b,$order,$kofactor,$base;
                  
                  
   public function __construct($seq) {
              
           $this->a = $seq->at(1)->asInteger()->number();
           $b = $seq->at(2)->asOctetString()->string();
           $a = Util::bstr2array($b) ;
           $a = array_reverse($a) ;   
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
           $a = array_reverse($a) ;   
           $ha = Util::array2hex($a) ;  
         
         
           $base  = Field::fromString($ha,16,$this)  ;
           
  //"2a29ef207d0e9b6c55cd260b306c7e007ac491ca1b10c62334a9e8dcd8d20fb6"
  
  //"4440441545504001551005441451450111150510414004505001450155400001544501041015044014501005014040505104441544051505140510400554514"
         $mm =   $base->mul($base) ;
         $h = $mm->toString(16) ;
         $dd =  $mm->div($base)  ;
         $hw = $dd[0]->toString(16) ;
       
         $this->base = $this->expand($base) ;
    
      
   }
    public   function expand($value ){
         
          $a = Field::fromString("".$this->a,10,$this) ;
          
     
          $b =  Field::fromBinary($this->b,$this );      
          
          $x =  Field::fromBinary($value,$this );      
          
          
          $bit = $x->testBit(0) ;
          $x->setBit(0,$bit) ;
         
          $trace = $x->trace();
          return  $p;
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
 
