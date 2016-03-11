
# Kerberos Chat
---
- [Осносные параметры](#Осносные-параметры)
- [Вход пользователя в систему](#Вход-пользователя-в-систему)
- [Аутентификация клиента](#Аутентификация-клиента)
- [Авторизация клиента на TGS](#Авторизация-клиента-на-TGS)
- [Взаимодействие с чатом](#Взаимодействие-с-чатом)
- [Разделение секрета](#Разделение-секрета)

---

## Краткое описание

Данное приложение демонстрирует работу протокола Керберос (авторизация пользователя) 
и схемы Шамира (разделение секрета - ключа для расшифровки переписки).


### Осносные параметры:

Шифрование: `AES128` (режим `CBC`, случайный `iv`)

Хеш: `SHA256`

Демо сервер: [https://kerberos-chat.herokuapp.com/](https://kerberos-chat.herokuapp.com/)
 - для AS добавить `as/login/` 
 - для TGS добавить `tgs/`
 - для чата: `ws://kerberos-chat.herokuapp.com/chat`

 - формат сообщения:
   ```json
   {
     "from": "username",
     "time": "2015-02-30 25:67:72",
     "room": "room_name",
     "text": "Hello world!"
   }
   ```

 - формат чата:
   ```json
   {
     "room": "id",
     "name": "name",
     "users": ["Alice", "Bob"],
     "threshold": 2
   }
   ``` 

## Вход пользователя в систему:

1. Пользователь вводит имя и пароль на клиентской машине.
2. Клиентская машина выполняет над паролем одностороннюю функцию (`SHA256`),
и результат становится секретным ключом клиента/пользователя.


## Аутентификация клиента:
1. Клиент отсылает запрос (`AS_REQ`) на СА для получения аутентификационных верительных данных и последующего их предоставления TGS серверу. 

 Данный запрос содержит:
  * Идентификатор клиента, его метка времени и идентификатор сервера.

    Отправлять через POST на 
    [https://ancient-fortress-4575.herokuapp.com/as/login](https://ancient-fortress-4575.herokuapp.com/as/login):

    POST parameter | Description 
    -------------- | --------
    login   | логин пользователя
    encrypted   | зашифрованный json, содержащий имя `tgs_name` и `timestamp`
        
    _например_: 
      ```json
      {
       "tgs_name": "tgs", 
       "timestamp": "2015-05-23 09:44:44"
      }
      ```
    
2. СА проверяет, есть ли такой клиент в базе. Если есть, то назад СА отправляет сообщение (`AS_REP`) включающее:
 * Сессионный ключ клиент/TGS, идентификатор TGS и время жизни билета зашифрованные секретным ключом клиента.
 * TGT (который включает идентификатор и сетевой адрес клиента, метку времени ЦРК, 
 период действия билета и сессионный ключ Клиент/TGS), зашифрованный секретным ключом TGS.
 
 ```json
 {
   "session_key": "secret_key",
   "user_login": "user",
   "user_ip": "127.92.14.24",
   "tgs_name": "tgs",
   "tgs_ticket_time_to_live": 60, 
   "session_key_time_to_live": 300,
   "timestamp": "2015-05-23 09:44:46"
 }
 ```
 
 * Если же нет, то клиент получает новое сообщение, говорящее о произошедшей ошибке.
 
 
  `AS_REP` *(до шифрования):*

   ```json
   {
     "tgs_ticket": "RUs2+XR ... XiM1", 
     "tgs_name": "tgs", 
     "time_to_live": 300, 
     "session_key": "r2trFew4TJI=" 
   }
   ```   
 
3. Получив сообщение, клиент его расшифровывает и получает сессионныё ключ Клиент/TGS. 
Этот сессионный ключ используется для дальнейшего обмена с сервером TGS. 

## Авторизация клиента на TGS:

1. Для запроса сервиса клиент формирует запрос на TGS (`TGS_REQ`) содержащий следующие данные:
 * TGT, полученный ранее и идентификатор сервиса.
 * Аутентификатор (составленный из ID клиента и временного штампа), 
 зашифрованный на Сессионном Ключе Клиент/TGS.

   Клиент шифрует аутентификатор (`authenticator`):
    ```json
    {
      "user_name": "client",
      "timestamp": "2015-05-23 09:44:47"
    }
    ```
    
   при помощи `session_key` и, затем, кодирует `base64`.
    
   И отправляет tgs (`tgs/`) используя `POST`:
    ```POST
    "authenticator": "...",
    "tgs_ticket": "...",
    "service": "chat"
    ```
    
2. После получения `TGS_REQ`, TGS извлекает из него TGT и расшифровывает его используя секретный ключ TGS. 
Это дает ему Сессионный Ключ Клиент/TGS (`session_key`). 
Им он расшифровывает аутентификатор. 
Затем он генерирует сессионный ключ клиент/сервис и посылает ответ (`TGS_REP`) включающий:
 * Билет сервиса (который содержит ID клиента, сетевой адрес клиента, метку времени ЦРК, 
 время действия билета и Сессионный Ключ клиент/сервис) зашифрованный секретным ключом сервиса.
 
  ```json
  {
    "user_login": "user_login",
    "user_ip": "127.92.14.24",
    "timestamp": "2015-05-23 09:44:47",
    "time_to_live": 300,
    "client_service_sk": "secure_sk"
  }
  ```
 
 * Сессионный ключ клиент/сервис, идентификатор сервиса и время жизни билета, зашифрованные на Сессионном Ключе Client/TGS.

  *Клиент получает json, рассшифровывает его при помощи `session_key` и видит нечто подобное:*
    ```json
    {
      "service": "chat", 
      "time_to_live": 1000000, 
      "client_service_sk": "NX784zLkOL0=", 
      "service_ticket": "T5z3ZHp ... Ew9sM+vUqh"
    }    
    ```
    
    
##  Взаимодействие с чатом
1. Клиент устанавливает соединения с сокетами. 
    `ws://ancient-fortress-4575.herokuapp.com/chat`

2. Проверка подлинности клиента и сервиса.
 * Клиент шифрует (используя `client_service_sk`) аутентификатор (`authenticator`):
 
    ```json
    {
      "user_name": "client",
      "timestamp": "2015-05-23 09:44:48"
    }
    ``` 

 * и отправляет по сокету json:
    
    ```json
    {
      "type": "login",
      "authenticator": "T5z3ZHp ... Ew9sM+vUqh",
      "service": "chat", 
      "service_ticket": "RUs2+XR ... XiM1"
    }    
    ```

3. Если авторизация прошла успешно, то он получит зашифрованный `client_service_sk` json примерно следующего содержания:
  
    ```json
    {
      "type": "handshake",
      "service": "chat", 
      "timestamp": "2015-05-23 09:44:45",
      "users_online": ["Vasya", "User"],
      "rooms": []
    }     
    ``` 
    подтвеждающий, что клиен связался с тем, кто ему нужен (клиент проверяет `service` и `timestamp`)
    
4. Дальнейшее общение организованно следующим образом:л 
 - отпрявлять запросы на сервер
 
   Type | Description | Params
   ---- | ----------- | ------
   `login` | Авторизация в системе | `service_ticket`, `authenticator`     
   `online` | Запрос доступных пользователей и чатов | `timestamp`
   `new_message` | json-описание сообщения | `message`, `room`, `timestamp`
   `new_room` | Запрос на создание нового чата | `room` (id чата), `threshold`, `users`, `timestamp`
   `go_room` | Вход в беседу | `room`, `secret`, `timestamp` 
   `secret` | Ответ на `get_secret` | `room`, `secret`, `timestamp`
   `delete_chat` | Удаление чата (удаляется пользователь, если `threshold` меньше количества участников чата) | `room`, `timestamp`
   `save_data` | Сохранение пользовательской информации на сервене (по ключу) | `key`, `data`, `timestamp`
   `get_data` | Получение пользовательской информации на сервене (словаря ключей) | `key`, `timestamp`

   *Я не уверен в необходимости, но в любом случае не помешает, отправлять ещё параметр `from` с каждым из сообщений.*

 - получать от сервера слудующие сообщения
 
   Type | Description | Params 
   -----| --------- | ------
   `handshake` | ответ на первый запрос клиента | `service`,`timestamp` 
   `online` | Пользователи онлайн и доступные чаты. |`users_online`, `rooms`, `timestamp` 
   `new_message` | Оповещение о новом сообщении (в том числе о своих сообщениях) | `new_message`, `room`, `timestamp`
   `new_room` | Оповещение о создинии нового чата | `room`, `secret`, `timestamp`
   `close_room` | Оповещение о закрытии чата (кто-то стал офлайн) | `room`, `timestamp`
   `get_secret` | Запрос секрета. | `room`, `timestamp`
   `room_messages` | История чата. | `room`, `messages`, `timestamp`
   `error` | Сообщение об ошибке | `error`, `timestamp`
   `data` | Пользовательская информация, хранящаяся на сервере (ответ на `get_data`). | `key`, `data`, `timestamp`
  
## Разделение секрета.

 Используется схема Шамира.
 
 В качестве модуля выбирается простое число из чисел Марсена или из простых, близких к степеням двойки.
 
 Генерируется случайный полином `f(x)` над полем выбранного простого числа степени `threshold - 1` и вычисляются его значения в точках `1, 2, ..., n`, где `n` - количество участников беседы.
 
 Эти значения и есть секреты, пользователям отправляются строки `"i-f(i)"`, а многочлен забывается.
  
 
