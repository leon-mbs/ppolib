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
   * распаковка
   * 
   * @param mixed $data
   */
   public  static function  decode($data) {
       $ret=[];
       $watchdoc=50;
       
       while(true)  {
           $pos = intval(strpos($data,"\0") );
        
           if($pos > 0 ){
               $label=substr($data,0,$pos )  ;
               $pos++;
               $len= substr($data,$pos,4) ;
               $dd= self::_U32($len);
      
               $content= substr($data,$pos+4,$dd )  ;
               $data = substr($data,$pos+4+$dd)  ;               
               $ret[$label] = $content;  
               
               if($label==="TRANSPORTABLE" || $label==="ZPOSTTRANSPORTABLE") {
                   $ret[$label] = [];
                   foreach(explode("\r\n",$content)  as $s) {
                      if(strpos($s,'=') > 0) {
                          $str=explode("=",$s)  ;    
                          $ret[$label][$str[0]] = trim($str[1]) ; 
                      }
                   }      
               }
           } else {
               break; 
           }
           if(--$watchdoc < 0){
               break;  
           }
       } 
       return $ret;
   }
 
   //упаковка в LE
   private static function U32($len) {
       $p=  pack('V',$len) ;
       return $p;
   }    
   //распаковка с LE
   private static function _U32($len) {
       $l=unpack('V',$len) ;
       return  array_shift($l) ;
   }  
}