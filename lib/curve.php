<?php
  
 
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
  use  \phpseclib3\Math\BigInteger;  
 
 class  Curve {
                    
   public $m,$ks,$a, $b,$order,$kofactor,$base;
                  
                  
   public function __construct($seq) {
              
           $this->a = $seq->at(1)->asInteger()->number();
           $this->b = $seq->at(2)->asOctetString()->string();
           $this->order  = $seq->at(3)->asInteger()->number() ;
           $base = $seq->at(4)->asOctetString()->string();
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
     
      
         
      
   }
   
   
   public function expandBP(){
       
   }
          
 }      
 
