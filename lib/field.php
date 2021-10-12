<?php
  
 
  
 
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
  
   
 class  Field   
 { 
    public $curve=null;  
    public $value=null;  
 
 
   
   public static function fromString($str,$base,$curve=null)  {
        
       $f = new  Field() ;
       $f->value =  gmp_init($str,$base) ;
       
       $f->curve = $curve;
       
       return $f;
        
   }
   public static function fromInt($v,$curve=null)  {
        
       $f = new  Field() ;
       $f->value =  gmp_init((int)$v) ;
       
       $f->curve = $curve;
       return $f; 
   }
   public static function fromBinary($v,$curve=null)  {
       $v =  Util::array2hex(Util::bstr2array($v)) ;
       $f = new  Field() ;
       $f->value =  gmp_init($v,16) ;
       
       $f->curve = $curve;
       return $f; 
   }
  
   public function toString($base=10 ) 
   {
        return gmp_strval($this->value,$base);
   } 
   
   public function testBit($i){
     return   gmp_testbit($this->value,$i) ;
   }
 
   public function setBit($i,$v){
         gmp_setbit($this->value,$i,$v) ;
   }
   public function trace(){
      return 0;
   }
   public function add($v){
      
       $this->value = gmp_xor($this->value,$v) ;
   }
   public function mul($v){
      $k1 = $this->KoefArray();
      $k2 = $v->KoefArray();
      
      
      
      $f =   self::FromKoefArray($k1);
   }
  
   private function KoefArray() {
       $bits =  gmp_strval($this->value,2);
       return  str_split($bits,1) ;
       
   }
   private static function FromKoefArray($a) {
      $bs =  implode(' ',$a) ;
       $bs = str_replace(' ','',$bs) ;
       $f = self::fromString($bs,2) ;
       
       return  $f;
       
   }
   
   // 84310
  //  85310
  
  
  //5∙7=(x^2+1)∙(x^2+x+1)=x^4+x^3+x^2+x^2+x+1=x^4+x^3+x+1=11011=27
    
    11011  111
    111    101
     0111
      111
     
      
        
 }