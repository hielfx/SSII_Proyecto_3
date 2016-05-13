# Proyecto 3 de la Asignatura Seguridad en Sistemas Informáticos e Internet
#### PSI 3. BYODSEC-BRING YOUR OWN DEVICE SEGURO PARA UNA EMPRESA USANDO SSL/TLS

Desarrollo de un sistema de simulación BYOD mediante sockets SSL/TLS que cumple los siguientes requisitos de seguridad:

1. **FR01** – Integridad de los mensajes: El servidor deberá comprobar la integridad de los mensajes en cada recepción.
2. **FR02** – Envío de NONCEs: El servidor deberá comprobar los NONCE enviados por el cliente para así evitar posibles ataques de replay.
3. **FR03** – Autenticación del cliente: El cliente deberá autenticarse mediante un usuario y contraseña conocido por el servidor. También se deberá usar certificados digitales para ello.
4. **FR04** – Autenticación del servidor: El servidor deberá autenticarse mediante un certificado (el cual debe conocer el cliente) para que así se pueda comprobar su identidad.
5. **FR05** – Colisiones: El sistema deberá evitar colisiones al utilizar los hashing seguros.
6. **FR06** – Confidencialidad: Los datos enviados entre el cliente y el servidor deberán estar cifrados con un algoritmo seguro para asegurar su confidencialidad.
7. **BR01** – Canal seguro: Los datos se deberán enviar a través de un canal seguro usando el Protocolo SSL/TLS
8. **IR01** – Información del mensaje: Se deberá almacenar información acerca del mensaje enviado, en concreto: NONCE, fecha de inserción, HMAC, contenido del mensaje, conservación de la integridad.
