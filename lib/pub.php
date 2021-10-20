<?php
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
 
 
 
 class Pub  {
     
   private $q;  
   public function __construct(Field $d ) {
       $p = $f->curve->base->mul($d);
       $this->q= $p->negate() ;
       
   }
   
   
   
 }
 
  