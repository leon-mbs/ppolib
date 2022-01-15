Библиотека  для  цифровой подписи документов, отправляемых в  налоговую (Украина)

Большинство  кода  портировано с [https://github.com/dstucrypt/jkurwa](https://github.com/dstucrypt/jkurwa)   

Установка 

composer require leon-mbs/ppolib

Как  использовать

Распаковка  ключа  и сертификата
   
   $cert =    \PPOLib\Cert::load($certdata) ;
   
   $key =   \PPOLib\KeyStore::load($keydata,$password,$cert ) ;

   Где
   $certdata - содержимое файла сертификата
   $keydata - содержимое файла ключа
   $password - пароль  к  ключу
   
   Поскольку  распаковка  происходит  довольно  медленно, обьекты     $cert и $key  следует 
   положить  в  сессию  или  сериализовать  и спрятать в  надежном  хранилище для дальнейшего использования
   
   
   Загрузка  jks файла (ПриватБанк)
   list($key,$cert) = \PPOLib\KeyStore::loadjks($jks,$password) ;
   
   В случае  неверной  работы  jks  ключа  на PHP x64 ключ  можно  сконвертировать в  key-6.dat
   (или  получить в  налоговой)  или  воспользоватся  сервером  подписи https://github.com/leon-mbs/internal-digital-signature-service
   
   
   Подпись  документа  или  команды
   
   $signeddata=  \PPOLib\PPO::sign('{"Command":"Objects"}'',$key,$cert);

   
   Отправка  запроса  в  налоговую
   
   $answer =  \PPOLib\PPO::send($signeddata,'cmd')  ;
   
   
   Если  отправляется  документ  ответом  будут  подписанные  данные, из  которых нужно вынуть документ ответа (обычно  xml)

   $data = \PPOLib\PPO::decrypt($answer,true) ;
   
   Если  предполагать  что ответ  с  налоговой  будет  подписан  верно  то  второй параметр (проверка  подписи) можно не  указывать
   это  ускорит  обработку.
   
   
