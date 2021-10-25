<?php

 
require_once __DIR__ . '/vendor/autoload.php';
 

define('_ROOT', __DIR__ . '/'); 

function lib_autoload($className) {
    $className = str_replace("\\", "/", ltrim($className, '\\'));

    if (strpos($className, 'PPOLib/') === 0) {
        $file = __DIR__ . DIRECTORY_SEPARATOR . 'lib'. DIRECTORY_SEPARATOR . strtolower($className) . ".php";
        $file = str_replace("ppolib/",'',$file ) ;
        if (file_exists($file)) {
            require_once $file;
        } else {
            die('Неверный класс ' . $className);
        }
    }
}

spl_autoload_register('lib_autoload'); 

 

   //  $cert  = file_get_contents(_ROOT . "/data/oldkey/8030938.cer") ;
  //   $key  = file_get_contents(_ROOT . "/data/oldkey/Key-6.dat") ;
  //    \PPOLib\KeyStore::load($key,"tectfom",$cert ) ;
    // $cert  = file_get_contents(_ROOT . "/data/newkey/EU.cer") ;
   //  $key  = file_get_contents(_ROOT . "/data/newkey/Key-6.dat") ;
   
   
  //   $cert =    \PPOLib\Cert::load($cert) ;
    // \PPOLib\KeyStore::load($key,"123qwe",$cert ) ;

      $cert =  file_get_contents(_ROOT . "data/cert" );
      $cert = unserialize($cert   ) ;
      $key = file_get_contents(_ROOT . "data/key2");
      $key = unserialize($key) ;

     $ms=  \PPOLib\PPO::sign("{\"Command\":\"Objects\"}",$key,$cert);
      file_put_contents(_ROOT . "data/newsign",$ms);