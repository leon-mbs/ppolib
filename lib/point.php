<?php
  
 
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
  
 
 class  Point
 {
      public $x;
      public $y;
      
      private $curve;
      
      public function __construct($x,$y){
           $this->x = $x;
           $this->y = $y;
           
      }
      
       
      
 }
 
 