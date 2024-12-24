## Библиотека  для наложения цифровой подписи  (КЕП)  согласно ДСТУ-4145

Большинство  кода  портировано с <https://github.com/dstucrypt/jkurwa>  

### Установка  


`composer require leon-mbs/ppolib`

### Как  использовать

   Распаковка сертификата и соответствующему  ему ключа (сертификат может  быть для  подписи или  шифрования и  соответственно разные  ключи)     
   ```
   $cert =    \PPOLib\Cert::load($certdata) ;  
   $key =   \PPOLib\KeyStore::load($keydata,$password,$cert ) ;
   ``` 
   Где
   $certdata - содержимое файла сертификата
   $keydata - содержимое файла ключа
   $password - пароль  к  ключу
   
   Поскольку  распаковка  происходит  довольно  медленно, обьекты     $cert и $key  следует 
   положить  в  сессию  или  сериализовать в  строки (файлы)  и спрятать в  надежном  хранилище 
   для дальнейшего использования путем  десериализации вмето распаковки
     
 
   
   Загрузка  jks файла (ПриватБанк)   
   `list($key,$cert) = \PPOLib\KeyStore::loadjks($jks,$password) ;`
   
 
   Подпись  документа  или  команды  
  ` $signeddata=  \PPOLib\PPO::sign($message,$key,$cert);`

   Открепленная  подпись (без данных)  
  ` $signeddata=  \PPOLib\PPO::sign($message,$key,$cert,true);`

   Подпись с  TSP отметкой  
   `$signeddata=  \PPOLib\PPO::sign($message,$key,$cert,false,true);`

   
   Отправка  запроса  в  налоговую
   
   `$answer =  \PPOLib\PPO::send($signeddata,'cmd')`  ;
   
   
   Если  отправляется  документ  ответом  будут  подписанные  данные, из  которых нужно вынуть документ ответа (обычно  xml)

   `$data = \PPOLib\PPO::decrypt($answer ) ;`
   
   Если ответ  с ФС то он  будет  подписан  верно  и можно поставить второй параметр  true что  ускорить  обработку.
   
   
   Получение информации о  подписи  
  `$info = \PPOLib\PPO::signinfo($answer) ;`
 
 
   Загрузка сертификата  с центра  сертификации  
   `\PPOLib\PPO::fetchCert($keydata,$pass  ) ;`
 
 
 
   Шифрование сообщения.  
   Использутся  пара  ключ-сертификат для  шифрования а  также  сертификат  получателя (ДФС)
   `\PPOLib\PPO::encipher($message,$forcert,$key,$keycert );`

   Дещифрование сообщения.  
     Использутся  пара  ключ  для  шифрования а  также  сертификат  получателя (ДФС)
   `\PPOLib\PPO::decipher($message,$key,$forcert );`
   
   
   Для отправки  в электронный кабинет  используются функции  
   
   `\PPOLib\DFS::encodeCrypt($encodedData,$h,$keycert ) ;`  
   `\PPOLib\DFS::encodeSign($signedData,$h ) ;`

   заголовок  
   `$h=\PPOLib\DFS::createHeader($keycert,"admin@gmail.com","test.txt") ;`  
   
   Примерная последовательность  

   шифруем данные  
   `$encoded= \PPOLib\PPO::encipher($message,$forcert,$key,$keycert);`

   `$h=\PPOLib\DFS::createHeader($keycert,"admin@gmail.com","test.txt");`

   упаковываем  
   `$transport=\PPOLib\DFS::encodeCrypt($encoded,$h,$keycert ) ;`

   если надо  подписать  
   ```
   $signed= \PPOLib\PPO::sign($transport,$key,$keycert);     
   $transport=\PPOLib\DFS::encodeSign($signed,$h ) ;
   ```
      
   распаковка  ответа налоговой
   `\PPOLib\DFS::decode($ticket ) ;`
      
   
   
   
