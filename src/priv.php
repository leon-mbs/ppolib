<?php
 namespace   PPOLib   ;
 
  
 use \PPOLib\Util ;
 
 
 /**
 * приватны ключ
 */
 class Priv  {
     
 
 
   public $d;  
   
   public function __construct($d,$curve,$le=false,$inv=false) {
       $c = new Curve($curve,$le) ;
       $d = Util::bstr2array($d) ;
       if($le) {
          $d  = array_reverse($d) ;   
       }
       if($inv) {
          $d  =Util::addzero(Util::invert($d));   
       }
       
       $this->d =   Field::fromString( Util::array2hex($d),16 ,$c) ;
        
       
       
   }
   
   // публичный ключ  на  основе приватного
   public  function pub(){
     
        
        return  new Pub($this->d);
   }

   /**
   *  подпись сообщения
   *  возвращает  цифровую  подпись
   */
   public  function sign($message){
       $buf = Util::bstr2array($message) ;
       $buf = array_reverse($buf) ;
       $buf =   Util::addzero($buf);
       
       $hv = Field::fromString(Util::array2hex($buf),16,$this->d->curve) ;
       $h44 = $hv->toString(16);
            
       $rand =  $this->d->curve->random();
     //  $rand = Field::fromString("690b17cd92dbb5c7b96a988de42401188895c4ca0267fb6c42ab68edb556e59e",16) ;
       
       
       $eG = $this->d->curve->base->mul($rand) ;
       $h = $eG->x->toString(16); 
       
       $r =  $hv->mulmod($eG->x) ;
       $r =  $this->d->curve->truncate($r) ;
       $hr = $r->toString(16); 
      
       $s = $this->d->mul($r)   ;
       $sh = $r->toString(16); 
       $sb = gmp_mul($this->d->value,$r->value) ;
       
       
       $s->value =  gmp_mod($sb,$this->d->curve->order->value) ;
       
       $sh = $r->toString(16); 
       $s->value =  gmp_add($s->value,$rand->value ) ;

       $s->value =  gmp_mod($s->value,$this->d->curve->order->value) ;
       
        
       $s->value =  gmp_mod($s->value,$this->d->curve->order->value) ;
 
 
      
       
       $ra = Util::hex2array($hr )   ;
       $sa = Util::hex2array($hs)   ;
       $buf = array_reverse(Util::hex2array($hs.$hr)  ) ;
   //06C848E8CE68E2996DBCDC80B36DCC7D31D9FF555F75B2362E34D213C7D4DE7E51EADC    
       $sign =  Util::array2bstr($buf);
       
     //  $pkey = $this->pub() ;
     //  $pkey->verify($message,$sign) ;
       return $sign;
   }
   
   
  
 }
 
  
 
 
 /*
SEQUENCE (4 elem)
  INTEGER 0
  SEQUENCE (2 elem)
    OBJECT IDENTIFIER 1.2.804.2.1.1.1.1.3.1.1       DSTU_4145_LE
    SEQUENCE (2 elem)
      SEQUENCE (5 elem)
        SEQUENCE (2 elem)
          INTEGER 257
          INTEGER 12
        INTEGER 0
        OCTET STRING (33 byte) 10BEE3DB6AEA9E1F86578C45C12594FF942394A7D738F9187E6515017294F4CE01
        INTEGER (256 bit) 5789604461865809771178549250434395392677236560479603245116974155309906…
        OCTET STRING (33 byte) B60FD2D8DCE8A93423C6101BCA91C47A007E6C300B26CD556C9B0E7D20EF292A00
   sbox   OCTET STRING (64 byte) A9D6EB45F13C708280C4967B231F5EADF658EBA4C037291D38D96BF025CA4E17F8E972…
 
 d  OCTET STRING (32 byte) 1B95E32D5A131162767BF57FA068BB09C7C9286B0317A35D766BAE7B19F0F40A
 
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
      OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.2.3        DSTU_4145_KEY_BITS
      SET (1 elem)
        BIT STRING (429 bit) 1111001010010101010110101101101011000100011100010111111111010000000010…
    SEQUENCE (2 elem)
      OBJECT IDENTIFIER 1.3.6.1.4.1.19398.1.1.2.2     DSTU_4145_CURVE
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
*/