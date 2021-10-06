<?php

namespace   PPOLib ;

use \PPOLib\Algo\Hash ; 
 
class Util
{

    public static function hex2array($hex, $to8 = false) {
        $s = str_split($hex, 2);
        $a = array();
        for ($i = 0; $i < count($s); $i++) {
            $a[$i] = hexdec($s[$i]);
        }
        if ($to8) {
            $c = 8 - count($a) % 8;

            for ($i = 0; $i < $c; $i++) {
                $a = array_merge($a, array(0));
            }

        }

        return $a;
    }


    public static function array2hex($a) {
      
         $ss = "";
         foreach($a as $v){
            $ss .= sprintf("%02X", $v);
            
         }
        return $ss;
    }

    //аналог >>>
    public static function rrr($a, $b) {
        if ($b >= 32 || $b < -32) {
            $m = (int)($b / 32);
            $b = $b - ($m * 32);
        }

        if ($b < 0) {
            $b = 32 + $b;
        }

        if ($b == 0) {
            return (($a >> 1) & 0x7fffffff) * 2 + (($a >> $b) & 1);
        }

        if ($a < 0) {
            $a = ($a >> 1);
            $a &= 0x7fffffff;
            $a |= 0x40000000;
            $a = ($a >> ($b - 1));
        } else {
            $a = ($a >> $b);
        }
        return $a;
    }


    public static function str2array($str, $to8 = false) {
        $a = unpack('C*', $str);

        if ($to8) {
            $c = 8 - count($a) % 8;

            for ($i = 0; $i < $c; $i++) {
                $a = array_merge($a, array(0));
            }

        }
        return $a;
    }


    public static function alloc($length,$v=0) {
        $a = array();
        for ($i = 0; $i < $length; $i++) {
            $a[$i] = $v;
        }
        return $a;
    }

    public static function bstr2array($str, $to8 = false) {
        $a = array();
        foreach (str_split($str, 1) as $c) {
         
            $a[] = ord($c);
        }

        if ($to8) {
            $c = 8 - count($a) % 8;

            for ($i = 0; $i < $c; $i++) {
                $a = array_merge($a, array(0));
            }

        }
        return $a;
    }

    public static function  array2bstr($array ) {
    
        $bstr  = pack('H*',Util::array2hex($array)  );; 
        return $bstr;
    }
    
    public static function sign($data ){
      
     
        $request = curl_init();

        curl_setopt_array($request, [
            CURLOPT_PORT => 3106,
            CURLOPT_URL =>  "127.0.0.1:3106/sign",
            CURLOPT_POST => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 20,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_POSTFIELDS => $data
        ]);

        $return = json_decode(curl_exec($request));

        if(curl_errno($request) > 0)
           {
                 
             return false;
             
           }  
         

        curl_close($request);

        return $return;
    }
 
  
  
    public static function decrypt1($data ){
      
  
  
        $request = curl_init();

        curl_setopt_array($request, [
            CURLOPT_PORT => 3000,
            CURLOPT_URL =>  "localhost:3000/decrypt",
            CURLOPT_POST => true,
            CURLOPT_ENCODING => "",
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 20,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_POSTFIELDS => base64_encode($data)    
        ]);

        $return =  (curl_exec($request));

        if(curl_errno($request) > 0)
           {
                
             return false;
             
           }           

        curl_close($request);

        return $return;
    }
 
     
    
    public static function convert_password($pass,$n=10000){
        $data = Util::str2array($pass)   ;
        $hash = new Hash();
        $hash->update($data);

        $ret = $hash->finish();
        $n--;
        while($n--){
          $hash = new Hash();
          $hash->update32($ret);

          $ret = $hash->finish();
            
        }
        return $ret;
    }   
}

