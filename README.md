# Firma con PKCS7 desde InterSystems IRIS



## QuickStart

* Compilar con Visual Studio 2019 el programa C++ FirmaPKCS7 para generar FirmaPKCS7.exe

* Cargar el codigo de ejemplo pkcs7.Demo.cls en IRIS

* Añadir al Certificate Store de Windows el Certificado X509 con el NIE a usar para la firma.

* Convertir el Certificado a una clave publica y una clave privada en format PEM.

  ```
  openssl pkcs12 -in path.p12 -out newfile.crt.pem -clcerts -nokeys
  openssl pkcs12 -in path.p12 -out newfile.key.pem -nocerts -nodes
  ```

* Crear una configuración SSL en IRIS para el envio

* Editar la clase de pkcs7.Demo.cls y modificar los valores de PARAMETERS

* Ejecutar la aplicación desde un prompt de Windows para validar que funcione:

  ```
  FirmaPKCS7.exe <NieEmpresa> c:\FirmaPKCS7\SampleEDI\EDI.TXT c:\FirmaPKCS7\SampleEDI\EDIFIRMADO.txt
  ```

  * La aplicación debe bucar el certificado con subject que contenha "NieEmpresa" en el Store de Windows, leer el fichero de ejemplo NIE.txt y producir EDIFIRMADO.txt

  * La Salida producida en pantalla debe ser así:

    ```
    Command-line arguments: argc=4
      argv[0]   FirmaPKCS7.exe
      argv[1]   NIEXXXXX
      argv[2]   EDI.TXT
      argv[3]   EDISIGNED.TXT
    Starting execution!
    CertStore:FindCertContext
    Subject:C=ES, SN=MiEmpredsa,  SERIALNUMBER=IDCES-X2628158V, CN=Mi Empresa NIE NIEXXXX
    FirmaDigital:Firma!
    FileTime Encriptado
    Mime Capabilities Encriptado
    Despues CryptSignMessage!
    Firma 
    <Firma en Base64>
    Done. Success.
    ```

    

* Probar desde un prompt de IRIS:

  ```
  USER>set sc=##class(pkcs7.Demo).Run()
  ```

  

