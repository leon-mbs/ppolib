<?php
  namespace   PPOLib   ;
 
 
 use \PPOLib\Util ;
 
 
 class KeyStore {
      
      
 
   
    public static function  load($keydata,$pass,$cert ) {
          
         $keys = array(); 
        
        
         $seq = \ASN1\Type\Constructed\Sequence::fromDER($keydata) ;
       //try  IIT
    
     
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
         
 
      
        //конвертим пароль
        /*
        $n=10000;
        $data = Util::str2array($pass)   ;
        $hash = new \PPOLib\Algo\Hash();
        $hash->update($data);

        $key = $hash->finish();
        $n--;
        while($n--){
          $hash = new \PPOLib\Algo\Hash();
          $hash->update32($key);

          $key = $hash->finish();
            
        }       
          */
       
        
      //  $key = Util::array2bstr($key) ;
         // file_put_contents(_ROOT . "data/convpass",$key) ;
          $key2 = file_get_contents(_ROOT . "data/convpass" ) ;
      $key = Util::bstr2array($key2) ;
         
         
         
         $gost = new \PPOLib\Algo\Gost() ;
         $key = $gost->key($key) ;
          $buf = array_merge($cbuf,$pad) ;
         $buf = $gost->decrypt($buf) ;
         
         $buf = array_slice($buf,0,count($cbuf)) ;
         
        // file_put_contents(_ROOT . "data/purekey",$buf);
     //  $keye = file_get_contents(_ROOT . "data/purekey" ) ;
     
         $seq = \ASN1\Type\Constructed\Sequence::fromDER(Util::array2bstr($buf)) ;
       
    
         $curveparams =    $seq->at(1)->asSequence()->at(1)->asSequence()->at(0)->asSequence();
         
           
         $param_d=  $seq->at(2)->asOctetString()->string();
       //  $d1= Util::bstr2array($param_d) ;
         
         $privkey1 =  new Priv($param_d,$curveparams)  ; 
         $keys[]=$privkey1;
          
          
          $attr = $seq->at(3)->asTagged()->asImplicit(16)->asSequence()  ;
         
          foreach($attr as $a) {
             $seq = $a->asSequence(); 
             $uid = $seq->at(0)->asObjectIdentifier()->oid();    
              
             if($uid=='1.3.6.1.4.1.19398.1.1.2.3' ){
               $param_d2=    $seq->at(1)->asSet()->at(0)->asBitString()->string();
               
                
             }  
             if($uid=='1.3.6.1.4.1.19398.1.1.2.2' ){
     
               $curve2 =   $seq->at(1)->asSet()->at(0)->asSequence()->at(0)->asSequence()  ;
              
 
             }  
          }     
     
          $privkey2 =  new Priv($param_d2,$curve2)  ; 
          
          $keys[]=$privkey2;
                 
          
      }  catch( \Exception $e)  {
         $msg = $e->getMessage() ;
      }
            
      //try  pbes
       /*
      try{
          $keydata  =substr($keydata,57); //skip pfx header
          $seq = \ASN1\Type\Constructed\Sequence::fromDER($keydata) ;
          foreach($seq as $bag) {
              $uid = $bag->at(0)->asObjectIdentifier()->oid() ;   //1.2.840.113549.1.12.10.1.2  (PKCS #12 BagIds
              
              $seq = $bag->at(1)->asTagged()->asImplicit(16)->asSequence()  ; 
              
              $seq =   $seq->at(0)->asSequence()  ;  
              $cryprData =  $seq->at(1)->asOctetString()->string();

              $PBES2 =   $seq->at(0)->asSequence()->at(1)->asSequence()  ;  
             
              $keyDerivation =   $PBES2->at(0)->asSequence()    ;  
              $uid = $keyDerivation->at(0)->asObjectIdentifier()->oid() ;   //1.2.840.113549.1.5.12 
      
              $salt = $keyDerivation->at(1)->asSequence()->at(0)->asOctetString()->string();
              $iter = $keyDerivation->at(1)->asSequence()->at(1)->asInteger()->number();
            
              $encryption =   $PBES2->at(1)->asSequence()    ;  
              $uid = $encryption->at(0)->asObjectIdentifier()->oid() ;   //1.2.804.2.1.1.1.1.1.1.3
              $iv =  $encryption->at(1)->asSequence()->at(0)->asOctetString()->string();
              $sbox =  $encryption->at(1)->asSequence()->at(1)->asOctetString()->string();
              
              
              
              //пароль
              $data = Util::str2array($pass)   ;
              $hash = new \PPOLib\Algo\Hash();
            
              $key = Util::alloc(32) ;
              $pw_pad36 = Util::alloc(32,0x36) ;
              $pw_pad5C = Util::alloc(32,0x5C) ;
              $ins = Util::alloc(4) ;
              $ins[3]=1;               
            
            for($k=0; $k < count($data); $k++) {
                $pw_pad36[$k] ^= $data[$k+1];
            }
            
            for($k=0; $k < count($data); $k++) {
                $pw_pad5C[$k] ^= $data[$k+1];
            }   
               
            $hash->update32($pw_pad36) ;  
            $hash->update(Util::str2array($salt)) ;  
            $hash->update($ins) ;  
            $h = $hash->finish() ;
            $hash = new \PPOLib\Algo\Hash();
             
            $hash->update32($pw_pad5C) ;  
            $hash->update32($h) ;  
            $h = $hash->finish() ;
       
            $iter--;
            for($k = 0; $k < 32; $k++) {
                $key[$k] = $h[$k];
            } 
            
            
            while ($iter-- > 0)  {
                $hash = new \PPOLib\Algo\Hash();
                $hash->update32($pw_pad36) ;  
                $hash->update32($h) ;  
                $h = $hash->finish() ;
           
                $hash = new \PPOLib\Algo\Hash();
                $hash->update32($pw_pad5C) ;  
                $hash->update32($h) ;  
                $h = $hash->finish() ;
         
         
                for($k = 0; $k < 32; $k++) {
                   $key[$k] ^= $h[$k];
                } 
       
            }
            
            
      $key2 = Util::array2bstr($key) ;
          file_put_contents(_ROOT . "data/convpass2",$key2) ;
       //  $key2 = file_get_contents(_ROOT . "data/convpass2" ) ;
     // $key = Util::bstr2array($key2) ;
             
            
            
            
            $gost = new \PPOLib\Algo\Gost() ;
            $key = $gost->key($key) ;

            $cryprData = Util::bstr2array($cryprData) ;
            $iv = Util::bstr2array($iv) ;

                         
            $buf = $gost->decrypt_cfb($iv,$cryprData);
            $buf = array_slice($buf,0,count($cryprData)) ;
          
            $parsed = Util::array2bstr($buf);
            
            
      file_put_contents(_ROOT . "data/purekey2",$parsed);
     //  $parsed = file_get_contents(_ROOT . "data/purekey2" ) ;
              
            
            $seq = \ASN1\Type\Constructed\Sequence::fromDER($parsed) ;
            
             $curveparams =    $seq->at(1)->asSequence()->at(1)->asSequence()->at(0)->asSequence();
             
               
             $param_d=  $seq->at(2)->asOctetString()->string();
              
             $privkey1 =  new Priv($param_d,$curveparams)  ; 
             $keys[]=$privkey1;
              
             $c = count($seq);  
          
                
                  
                     
          } //bag
         
         
      } 
      catch (\Exception $e)
        {
            $m = $e->getMessage() ;
        }
         
       */
   
    
     //  file_put_contents(_ROOT . "data/keys",serialize($keys));
      // $keys = unserialize(file_get_contents(_ROOT . "data/keys2" ) );
      
    
          $cert = Cert::load($cert) ;
       //   $p = $cert->getPub() ;
       }
  }   
  
  /*
SEQUENCE (4 elem)
  INTEGER 0
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
    SEQUENCE (2 elem)
      SEQUENCE (5 elem)
        SEQUENCE (2 elem)
          INTEGER 257
          INTEGER 12
        INTEGER 0
        OCTET STRING (33 byte) 10BEE3DB6AEA9E1F86578C45C12594FF942394A7D738F9187E6515017294F4CE01
        INTEGER (256 bit) 5789604461865809771178549250434395392677236560479603245116974155309906…
        OCTET STRING (33 byte) B60FD2D8DCE8A93423C6101BCA91C47A007E6C300B26CD556C9B0E7D20EF292A00
      OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
  OCTET STRING (32 byte) 1B95E32D5A131162767BF57FA068BB09C7C9286B0317A35D766BAE7B19F0F40A
  [0] (5 elem)
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.2.1
      SET (1 elem)
        OCTET STRING (32 byte) A6B1F3FFE570744BF13E4D0F07DA15B086350EC82D3882852DD7249D8AAB6BFC
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.2.5
      SET (1 elem)
        OCTET STRING (32 byte) D8B614529815BD9E0D88A0B22AB3F5318D05140E7895D4A52967D54ABA3A53F3
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.2.3
      SET (1 elem)
        BIT STRING (429 bit) 1111001010010101010110101101101011000100011100010111111111010000000010…
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.2.2
      SET (1 elem)
        SEQUENCE (3 elem)
          SEQUENCE (5 elem)
            SEQUENCE (2 elem)
              INTEGER 431
              SEQUENCE (3 elem)
                INTEGER 5
                INTEGER 3
                INTEGER 1
            INTEGER 1
            OCTET STRING (54 byte) 03CE10490F6A708FC26DFE8C3D27C4F94E690134D5BFF988D8D28AAEAEDE975936C66B…
            INTEGER (430 bit) 2772669694120814859578414184143083703436437075375816575170479580585904…
            OCTET STRING (54 byte) 1A62BA79D98133A16BBAE7ED9A8E03C32E0824D57AEF72F88986874E5AAE49C27BED49…
          OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
          OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.2.6
      SET (1 elem)
        SEQUENCE (3 elem)
          OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
          OCTET STRING (8 byte) BCAB44C7D9B4C5E4
          OCTET STRING (32 byte) 754CBBAE090D47141D281D4D18E4CB1CFA3858EBA67C15EC01742B79F74C0221
          
          
SEQUENCE (3 elem)
  INTEGER 0
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1
    SEQUENCE (2 elem)
      SEQUENCE (5 elem)
        SEQUENCE (2 elem)
          INTEGER 257
          INTEGER 12
        INTEGER 0
        OCTET STRING (33 byte) 10BEE3DB6AEA9E1F86578C45C12594FF942394A7D738F9187E6515017294F4CE01
        INTEGER (256 bit) 5789604461865809771178549250434395392677236560479603245116974155309906…
        OCTET STRING (33 byte) B60FD2D8DCE8A93423C6101BCA91C47A007E6C300B26CD556C9B0E7D20EF292A00
      OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
  OCTET STRING (32 byte) 211A283A6CD939E7E93B652A8B9FF56746382582350260C169349FF7813BAD7C          
          
          */
  
 