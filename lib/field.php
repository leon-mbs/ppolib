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
  
   public function getLength( ) 
   {
        return strlen(gmp_strval($this->value,10) );
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
      $kout =   Util::alloc(count($k1)+count($k2)) ;

      for($i1 = 0;$i1<count($k1) ;$i1++){
          if($k1[$i1]==0) continue ;
          for($i2 =0;$i2< count($k2) ;$i2++){
              if($k2[$i2]==0) continue ;
              $i = $i1+$i2;
              if($kout[$i]==1) {
                 $kout[$i]=0; 
              }   else {
                  $kout[$i]=1;
              }
              
          }
      }
      
      $kout = array_reverse($kout)  ;
      
      $f =   self::FromKoefArray($kout);
      $f->curve = $this->curve;
      if($f->curve==null) $f->curve = $v->curve;
      
      
      return $f;
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
   
   public static function get0($curve=null)  {
        
       $f = new  Field() ;
       $f->value =  gmp_init((int)0) ;
       
       $f->curve = $curve;
       return $f; 
   }   
   
   
   public function mod(){
         
          $m = Field::get0(null) ;
          $m->setBit(8,1) ;
          $m->setBit(4,1) ;
          $m->setBit(3,1) ;
          $m->setBit(1,1) ;
          $m->setBit(0,1) ;
  
  
          return $this->div($m) ;
             
       
   }
    public function div($v){
        
    }
  
   
   
   // 84310
  //  85310
  
  
  //5∙7=(x^2+1)∙(x^2+x+1)=x^4+x^3+x^2+x^2+x+1=x^4+x^3+x+1=11011=27
    
   // 11011  111
  //  111    101
  //   0111
  //    111
     
      
        
 }