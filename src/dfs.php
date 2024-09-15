<?php    

namespace PPOLib;

use \PPOLib\Util ;
/**
* упаковка  отчетности для  отправки в  электронный кабинет
*/
class DFS
{
   /**
   * для  отправки  подписаных  данных
   *  
   * @param mixed $signeddata
   * @param mixed $header  Заголовок
   * @param Cert $cert   сертификат (необязательно)
   */
   public  static function  encodeSign($signeddata,$header='',Cert $cert=null) {
      $docs = [];
      if($cert != null){
         $docs['CERTCRYPT']=$cert->asBinary();  ;    
      }
      $docs['UA1_SIGN']=$signeddata; 
      
      return self::encode($docs,$header) ;
   }

   
   /**
   * для  отправки зашифрованых данных
   * 
   * @param mixed $encrypteddata
   * @param mixed $header
   * @param Cert $cert
   */
   public  static function  encodeCrypt($encrypteddata,$header='',Cert $cert=null) {
     $docs = [];
      if($cert != null){
         $docs['CERTCRYPT']=$cert->asBinary();    
      }
      $docs['UA1_CRYPT']=$encrypteddata;    
      return self::encode($docs,$header) ;
              
   }
   
   private  static function  encode($docs,$header='') {
       $ret='';   
       if(strlen(trim($header))>0) {
          $ret = $header;    
       }  
       foreach($docs as $k=>$c) {
          $ret = $ret.$k."\0" ;
          $ret = $ret.self::U32(strlen($c)) ;
          $ret = $ret.$c ;
          
       }
       
       return $ret; 
   }
   
   
   /**
   * генерация  заголовка 
   * 
   * @param Cert $cert  сертификат отправителя
   * @param mixed $email (неодязательно)
   * @param mixed $filename (неодязательно)
   */
   public static function createHeader(Cert $cert,$email='',$filename='') {
    
        $header=[];
        
        if(strlen($email)>0)  {
          $header['RCV_EMAIL'] = $email ;  
        } 
        if(strlen($filename)>0)  {
          $header['FILENAME'] = $filename ;  
        } 
        $header['CERTYPE'] = 'UA1' ;  
        $header['PRG_TYPE'] = 'PPOLib' ;  
        $header['PRG_VER'] = '2.0.0' ;  
        $header['SND_DATE'] = substr(date('YmdHis'),0,14);   
        $header['RCV_NAME'] =  $cert->getOwnerName();  
        $header['RCV_NAME']  = iconv('UTF-8','windows-1251',$header['RCV_NAME']);  
        $header['EDRPOU'] = $cert->getTIN() ;  



        $buf='';
        foreach($header as $k=>$v) {
           $buf = $buf. $k."=".$v."\r\n" ;            
        }
        $buf = $buf."\0" ;
        $ret = "TRANSPORTABLE\0" ;
        
        $ret = $ret. self::U32(strlen($buf));
        $ret = $ret. $buf;
        return $ret;
   }
 
   /**
   * разпаковка
   * 
   * @param mixed $data
   */
   public  static function  decode($data) {
       $ret=[];
       while(strlen($data)>0)  {
           $hp= strpos($data,"TRANSPORTABLE")  ;
           if($hp === 0) {
               $len= substr($data,14,4) ;
               $dd= self::_U32($len);
               $hd= substr($data,18,$dd )  ;
               
               $ret['header'] =[];
               foreach(explode("\r\n",$hd)  as $s) {
                  if(strpos($s,'=')>0) {
                    $str=explode("=",$s)  ;    
                    $ret['header'][$str[0]] = trim($str[1]) ; 
                  }
                  
                  
               }
               $data = substr($data,18+$dd)  ;
               
           }
           $us= strpos($data,"UA1_SIGN")  ;
           if($us === 0) {
               $len= substr($data,9,4) ;
               $dd= self::_U32($len);
               $sd= substr($data,13,$dd )  ;
               $ret['UA1_SIGN'] = $sd; 
               
               $data = substr($data,13+$dd)  ;
   
                     
           }
           $us= strpos($data,"UA1_CRYPT")  ;
           if($us === 0) {
               $len= substr($data, 10,4) ;
               $dd= self::_U32($len);
               $sd= substr($data, 14,$dd )  ;
               $ret['UA1_CRYPT'] = $sd;     
               $data = substr($data,14+$dd)  ;
 
          }
           $us= strpos($data,"CERTCRYPT")  ;
           if($us === 0) {
               $len= substr($data,10,4) ;
               $dd= self::_U32($len);
               $sd= substr($data,14,$dd )  ;
               $ret['CERTCRYPT'] = $sd;     
               $data = substr($data,14+$dd)  ;
 
          }
       } 
       return $ret;
       
   }
 
 
 
   //упаковка в LE
   private static function U32($len) {
       $p=  pack('V',$len) ;
       return $p;
   }    
   //распаковка LE
   private static function _U32($len) {
       $l=unpack('V',$len) ;
       return  array_shift($l) ;
   }  
}