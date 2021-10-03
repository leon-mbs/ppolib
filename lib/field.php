<?php
  
 
  
 
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
  
   
 class  Field   
 { 
    public $curve=null;  
    public $value=null;  
 
    public function __construct($value,$curve) {
       
      
       
       $this->value = $value;
       $this->curve = new Curve($curve);
       
       
       
   }    
 }