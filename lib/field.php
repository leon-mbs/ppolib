<?php
  
 
  
 
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
  
   
 class  Field   
 { 
    public $curve=null;  
 
    public function __construct($value,$curve) {
       
      
       
       $this->curve = new Curve($curve);
       
       
       
   }    
 }