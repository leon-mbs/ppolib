<?php
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
 
 
 
 class Pub  {
     
   public $q;  
   public function __construct(Field $d ) {
       
     
       $p = $d->curve->base->mul($d);
 
    
       $this->q= $p->negate() ;
   
    
     
   }
   
    public  function verify($message,$sign){
        
        return  ;
   } 
   
 }
 
  