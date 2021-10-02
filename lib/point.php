<?php
  
 
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
 use  \phpseclib3\Math\BigInteger; 
 
 class  Point
 {
      public $x;
      public $y;
      
      private $curve;
      
      public function __construct($curve){
           $this->curve = $curve;
           
      }
      
      public static function expand($curve,$value){
         
     //  "1a62ba79d98133a16bbae7ed9a8e03c32e0824d57aef72f88986874e5aae49c27bed49a2a95058068426c2171e99fd3b43c5947c857c"       
          
          $p = new Point($curve);
          
       
          $value = $value  ;
          
          
          return  $p;
      }     
      
 }
 
 