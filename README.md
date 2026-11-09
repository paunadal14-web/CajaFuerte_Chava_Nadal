# CajaFuerte_Apellido1_Apellido2

Aplicación de consola en C# (.NET 8) que cifra y descifra ficheros `.txt` con **AES-256-GCM** y una clave derivada de contraseña con **PBKDF2-HMAC-SHA256 (600.000 iteraciones)**.

## Uso

```bash
dotnet run -- cifrar    <fichero_entrada.txt> <fichero_salida.caja> <contraseña>
dotnet run -- descifrar <fichero_salida.caja> <fichero_recuperado>  <contraseña>
```

O, una vez compilado (`dotnet build -c Release`):

```bash
CajaFuerte cifrar    secreto.txt secreto.caja "MiContraseña"
CajaFuerte descifrar secreto.caja recuperado.txt "MiContraseña"
```

Códigos de salida: `0` correcto · `1` uso incorrecto · `2` error de fichero · `3` **fallo de integridad** (fichero manipulado o contraseña incorrecta).

## Cumplimiento de los requisitos técnicos

| Requisito | Implementación |
|---|---|
| Algoritmo | AES con clave de 32 bytes → AES-256 |
| Modo | `AesGcm` (cifrado autenticado), tag de 16 bytes |
| Derivación de clave | `Rfc2898DeriveBytes.Pbkdf2` con `HashAlgorithmName.SHA256`, 600.000 iteraciones |
| Sal | 16 bytes de `RandomNumberGenerator.GetBytes`, nueva en cada fichero |
| Nonce / IV | 12 bytes de `RandomNumberGenerator.GetBytes`, nuevo en cada cifrado |
| Aleatoriedad | Sólo `RandomNumberGenerator`; `System.Random` no aparece en el código |
| Integridad | `AesGcm.Decrypt` verifica el tag; si falla lanza `AuthenticationTagMismatchException`, se avisa y **no se escribe** el fichero de salida |
| Prohibidos | No se usa DES, 3DES, RC4, MD5, SHA-1 ni ECB |
| Contraseña | Llega por argumento; nunca está en el código. La clave derivada se borra de memoria con `CryptographicOperations.ZeroMemory` |

## Formato del fichero `.caja`

| Offset | Longitud | Bloque |
|---|---|---|
| 0 (0x00) | 4 B | Firma ASCII `CAJA` (`43 41 4A 41`) |
| 4 (0x04) | 1 B | Versión `0x01` |
| 5 (0x05) | 16 B | **1. Sal** (PBKDF2) |
| 21 (0x15) | 12 B | **2. Nonce** (AES-GCM) |
| 33 (0x21) | 16 B | **3. Tag** de autenticación |
| 49 (0x31) | N B | **4. Texto cifrado** (hasta el final del fichero) |

Tamaño total = 49 + tamaño del `.txt` original. La firma y la versión se pasan a GCM como datos asociados (AAD), así que también están protegidas contra modificaciones.

## Fichero de verificación

`ejemplo/mensaje_secreto.caja` está cifrado con una contraseña que se entrega **en un documento aparte**, no en este repositorio.

## Pregunta: *"Si guardaras la clave de cifrado en el mismo sitio que el fichero cifrado, ¿qué habrías conseguido realmente?"*

Nada de seguridad real: sería como cerrar la caja fuerte con llave y dejar la llave pegada a la puerta. Quien consiga acceder al fichero cifrado tendría también la clave, de modo que podría descifrarlo (e incluso modificarlo y volver a generar un tag válido) sin ningún esfuerzo. La fortaleza de AES-256 deja de importar, porque la seguridad no depende del algoritmo sino de mantener la clave en secreto (principio de Kerckhoffs). Por eso la clave, o la contraseña de la que se deriva, debe guardarse separada de los datos que protege.
