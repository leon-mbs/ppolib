<?php
  namespace   PPOLib   ;
 
 
 use \PPOLib\Util ;
 
 
 class KeyStore {
      
      
 
   
    public static function  load($keydata,$pass ) {
          
         $keys = array(); 
        
        
         $seq = \ASN1\Type\Constructed\Sequence::fromDER($keydata) ;
      
      try{   
         
         $uid = $seq->at(0)->asSequence()->at(0)->asObjectIdentifier()->oid()  ;
          
         
         if($uid!="1.3.6.1.4.1.19398.1.1.1.2") {  //IIT Store
             throw new  \Exception("Неверное хранилище  ключа");
         }  
         
         $cryptParam = $seq->at(0)->asSequence()->at(1)->asSequence()   ;
        
         $mac = $cryptParam->at(0)->asOctetString()->string() ;
         $pad = $cryptParam->at(1)->asOctetString()->string() ;
     
         
         $cryptData =  $seq->at(1)->asOctetString()->string() ;
        
         $mac = Util::bstr2array($mac) ;
         $pad = Util::bstr2array($pad) ;
         $cbuf = Util::bstr2array($cryptData) ;
       //  $key = Util::convert_password($pass) ;
       
        //конвертим пароль
        $n=10000;
        $data = Util::str2array($pass)   ;
        $hash = new \PPOLib\Algo\Hash();
        $hash->update($data);

        $key = $hash->finish();
        $n--;
        while($n--){
          $hash = new \PPOLib\Algo\Hash();
          $hash->update32($ret);

          $key = $hash->finish();
            
        }       
       
       
         // 163,237 ,61  ,241,37
      //  $key = Util::array2bstr($key) ;
         // file_put_contents(__DIR__ . "/convpass",$key) ;
       //  $key2 = file_get_contents(_ROOT . "data/convpass" ) ;
    //  $key2 = Util::bstr2array($key2) ;
         
         $gost = new \PPOLib\Algo\Gost() ;
         $key = $gost->key($key) ;
          $buf = array_merge($cbuf,$pad) ;
         $buf = $gost->decrypt($buf) ;
         
         $buf = array_slice($buf,0,count($cbuf)) ;
         
        // file_put_contents(__DIR__ . "/purekey",$buf);
     //  $keye = file_get_contents(_ROOT . "data/purekey" ) ;
     
         $seq = \ASN1\Type\Constructed\Sequence::fromDER(Util::array2bstr($buf)) ;
       
    
         $curveparams =    $seq->at(1)->asSequence()->at(1)->asSequence()->at(0)->asSequence();
         
           
         $param_d=  $seq->at(2)->asOctetString()->string();
         $d1= Util::bstr2array($key['param_d']) ;
         
         $privkey1 =  new Priv($d1,$curveparams)  ; 
          $keys[]=$privkey1;
          
          
          $attr = $seq->at(3)->asTagged()->asImplicit(16)->asSequence()  ;
         
          foreach($attr as $a) {
             $seq = $a->asSequence(); 
             $uid = $seq->at(0)->asObjectIdentifier()->oid();    
              
             if($uid=='1.3.6.1.4.1.19398.1.1.2.3' ){
               $param_d2=    $seq->at(1)->asSet()->at(0)->asBitString()->string();
               
               $d2= Util::bstr2array($param_d2) ;
             }  
             if($uid=='1.3.6.1.4.1.19398.1.1.2.2' ){
     
               $curve2 =   $seq->at(1)->asSet()->at(0)->asSequence()->at(0)->asSequence()  ;
              
 
             }  
          }     
     
          $privkey2 =  new Priv($d2,$curve2)  ; 
          
          $keys[]=$privkey2;
                 
          
      }  catch( \Exception $e)  {
         $msg = $e->getMessage() ;
      }
         
       return $keys;
    }
    
       //   $cert = Cert::load($cert) ;
       //   $p = $cert->getPub() ;
    
  }   
  
  /*
  SEQUENCE (2 elem)
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.1.2
    SEQUENCE (2 elem)
      OCTET STRING (4 byte) 428DFA97
      OCTET STRING (4 byte) EA37DA5B
  OCTET STRING (908 byte) 4B310EE3BF0F81A40514ACB314FC491332EF7DA0B3F74E7975B8A3F31E5F2078A7970…
  */
  
 