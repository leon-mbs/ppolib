<?php
  
 
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
  
 
 class  Point
 {
      public $x;
      public $y;
       
      public function __construct($x,$y){
            
           $this->x = $x;
           $this->y = $y;
            
         
      }
 
 
     public function mul(Field $f){
         
     }
     public function negate(){
        return new Point(  $this->x, $this->x->add($this->y));
  
     }
     public function isequal($p){
         
     }
      
 }
 
 