/*
 * =============================================================================
 *  CajaFuerte  -  Cifrado y descifrado de ficheros .txt con AES-256-GCM
 * =============================================================================
 *
 *  USO
 *    CajaFuerte cifrar    <fichero_entrada.txt>  <fichero_salida.caja>  <contraseña>
 *    CajaFuerte descifrar <fichero_salida.caja>  <fichero_recuperado>   <contraseña>
 *
 *  ESTÁNDARES APLICADOS
 *    - Algoritmo ........ AES-256 (clave de 32 bytes)
 *    - Modo ............. GCM (cifrado autenticado) mediante System.Security.Cryptography.AesGcm
 *    - Derivación clave . PBKDF2 (Rfc2898DeriveBytes.Pbkdf2) con HMAC-SHA256, 600.000 iteraciones
 *    - Sal .............. 16 bytes aleatorios (RandomNumberGenerator), nueva en cada fichero
 *    - Nonce (IV) ....... 12 bytes aleatorios (RandomNumberGenerator), nuevo en cada cifrado
 *    - Tag .............. 16 bytes (128 bits), generado por GCM
 *    - Aleatoriedad ..... RandomNumberGenerator. No se usa System.Random en ningún sitio.
 *    - No se usa DES, 3DES, RC4, MD5, SHA-1 ni el modo ECB.
 *
 *  FORMATO BINARIO DEL FICHERO .caja  (todos los bloques de longitud FIJA,
 *  salvo el texto cifrado, que ocupa todo lo que queda hasta el final)
 *
 *    Offset (dec)  Offset (hex)  Longitud  Contenido
 *    ------------  ------------  --------  -----------------------------------------
 *         0          0x00         4 B     Firma mágica: ASCII "CAJA" (43 41 4A 41)
 *         4          0x04         1 B     Versión del formato: 0x01
 *         5          0x05        16 B     (1) SAL usada en PBKDF2
 *        21          0x15        12 B     (2) NONCE / IV usado en AES-GCM
 *        33          0x21        16 B     (3) TAG de autenticación de GCM
 *        49          0x31         N B     (4) TEXTO CIFRADO (N = tamaño del .txt original)
 *
 *    Tamaño total del .caja = 49 + N bytes.
 *
 *    La cabecera (firma + versión, bytes 0..4) se pasa a GCM como "datos
 *    asociados" (AAD): no va cifrada, pero sí autenticada. Si alguien cambia
 *    un solo bit de la cabecera, de la sal, del nonce, del tag o del texto
 *    cifrado, la verificación del tag falla y el fichero se rechaza.
 *    (Cambiar la sal o el nonce hace que se derive otra clave / otro flujo, y
 *    el tag deja de coincidir igualmente.)
 *
 *  INTEGRIDAD
 *    AesGcm.Decrypt comprueba el tag automáticamente ANTES de devolver ningún
 *    dato. Si no coincide lanza AuthenticationTagMismatchException; el programa
 *    la captura, muestra un aviso claro y NO escribe el fichero de salida.
 *    El texto descifrado sólo se escribe en disco si la verificación ha sido
 *    correcta, de modo que nunca se entregan datos corruptos en silencio.
 *
 *  La contraseña NO está en el código: se recibe por línea de comandos.
 *  La clave derivada sólo vive en memoria y se borra (ZeroMemory) al terminar.
 * =============================================================================
 */

using System.Security.Cryptography;
using System.Text;

namespace CajaFuerte;

public static class Program
{
    // ---- Parámetros del formato y de la criptografía -----------------------
    private static readonly byte[] Firma = Encoding.ASCII.GetBytes("CAJA");
    private const byte Version = 0x01;

    private const int TamFirma = 4;
    private const int TamVersion = 1;
    private const int TamCabecera = TamFirma + TamVersion; // 5
    private const int TamSal = 16;     // 128 bits (mínimo exigido: 16 bytes)
    private const int TamNonce = 12;   // 96 bits, tamaño estándar recomendado para GCM
    private const int TamTag = 16;     // 128 bits, tag completo de GCM
    private const int TamClave = 32;   // 256 bits -> AES-256
    private const int Iteraciones = 600_000; // recomendación OWASP para PBKDF2-HMAC-SHA256

    private const int OffsetSal = TamCabecera;              // 5
    private const int OffsetNonce = OffsetSal + TamSal;     // 21
    private const int OffsetTag = OffsetNonce + TamNonce;   // 33
    private const int OffsetCifrado = OffsetTag + TamTag;   // 49

    // Códigos de salida
    private const int Ok = 0;
    private const int ErrorUso = 1;
    private const int ErrorFichero = 2;
    private const int ErrorIntegridad = 3;

    public static int Main(string[] args)
    {
        if (!AesGcm.IsSupported)
        {
            Console.Error.WriteLine("ERROR: AES-GCM no está disponible en este sistema.");
            return ErrorUso;
        }

        if (args.Length != 4)
        {
            MostrarUso();
            return ErrorUso;
        }

        string operacion = args[0].ToLowerInvariant();
        string entrada = args[1];
        string salida = args[2];
        string contrasena = args[3];

        if (string.IsNullOrEmpty(contrasena))
        {
            Console.Error.WriteLine("ERROR: la contraseña no puede estar vacía.");
            return ErrorUso;
        }

        try
        {
            switch (operacion)
            {
                case "cifrar":
                    if (!Path.GetExtension(entrada).Equals(".txt", StringComparison.OrdinalIgnoreCase))
                    {
                        Console.Error.WriteLine("ERROR: el fichero de entrada debe tener extensión .txt");
                        return ErrorUso;
                    }
                    Cifrar(entrada, salida, contrasena);
                    Console.WriteLine($"OK: '{entrada}' cifrado correctamente en '{salida}'.");
                    return Ok;

                case "descifrar":
                    Descifrar(entrada, salida, contrasena);
                    Console.WriteLine($"OK: integridad verificada. Fichero recuperado en '{salida}'.");
                    return Ok;

                default:
                    MostrarUso();
                    return ErrorUso;
            }
        }
        catch (AuthenticationTagMismatchException)
        {
            // GCM ha detectado que el tag no coincide: contraseña incorrecta o
            // fichero manipulado. No se ha escrito ningún dato descifrado.
            Console.Error.WriteLine("ALERTA DE INTEGRIDAD: el fichero ha sido manipulado o la contraseña es incorrecta.");
            Console.Error.WriteLine("No se ha descifrado nada y no se ha generado el fichero de salida.");
            return ErrorIntegridad;
        }
        catch (FormatoInvalidoException ex)
        {
            Console.Error.WriteLine($"ALERTA DE INTEGRIDAD: {ex.Message}");
            Console.Error.WriteLine("No se ha descifrado nada y no se ha generado el fichero de salida.");
            return ErrorIntegridad;
        }
        catch (FileNotFoundException ex)
        {
            Console.Error.WriteLine($"ERROR: no se encuentra el fichero '{ex.FileName}'.");
            return ErrorFichero;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            Console.Error.WriteLine($"ERROR de E/S: {ex.Message}");
            return ErrorFichero;
        }
    }

    // ========================================================================
    //  CIFRAR
    // ========================================================================
    public static void Cifrar(string rutaEntrada, string rutaSalida, string contrasena)
    {
        byte[] textoPlano = File.ReadAllBytes(rutaEntrada);

        // Sal y nonce NUEVOS y aleatorios en cada operación (CSPRNG).
        byte[] sal = RandomNumberGenerator.GetBytes(TamSal);
        byte[] nonce = RandomNumberGenerator.GetBytes(TamNonce);

        byte[] cifrado = new byte[textoPlano.Length];
        byte[] tag = new byte[TamTag];
        byte[] cabecera = ConstruirCabecera();

        byte[] clave = DerivarClave(contrasena, sal);
        try
        {
            using var aes = new AesGcm(clave, TamTag);
            // La cabecera se autentica como AAD (no se cifra, pero no se puede alterar).
            aes.Encrypt(nonce, textoPlano, cifrado, tag, cabecera);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clave);
            CryptographicOperations.ZeroMemory(textoPlano);
        }

        // Escritura en el orden documentado: cabecera | sal | nonce | tag | cifrado
        using var fs = new FileStream(rutaSalida, FileMode.Create, FileAccess.Write);
        fs.Write(cabecera);
        fs.Write(sal);
        fs.Write(nonce);
        fs.Write(tag);
        fs.Write(cifrado);
    }

    // ========================================================================
    //  DESCIFRAR
    // ========================================================================
    public static void Descifrar(string rutaEntrada, string rutaSalida, string contrasena)
    {
        byte[] datos = File.ReadAllBytes(rutaEntrada);

        // 1) Comprobaciones estructurales antes de tocar la criptografía.
        if (datos.Length < OffsetCifrado)
            throw new FormatoInvalidoException(
                $"el fichero es demasiado corto ({datos.Length} bytes) para ser un .caja válido (mínimo {OffsetCifrado}).");

        byte[] cabecera = datos.AsSpan(0, TamCabecera).ToArray();
        if (!cabecera.AsSpan(0, TamFirma).SequenceEqual(Firma))
            throw new FormatoInvalidoException("la firma 'CAJA' no es correcta: no es un fichero de CajaFuerte o está dañado.");
        if (cabecera[TamFirma] != Version)
            throw new FormatoInvalidoException($"versión de formato desconocida (0x{cabecera[TamFirma]:X2}).");

        // 2) Extraer cada bloque según los offsets documentados.
        ReadOnlySpan<byte> sal = datos.AsSpan(OffsetSal, TamSal);
        ReadOnlySpan<byte> nonce = datos.AsSpan(OffsetNonce, TamNonce);
        ReadOnlySpan<byte> tag = datos.AsSpan(OffsetTag, TamTag);
        ReadOnlySpan<byte> cifrado = datos.AsSpan(OffsetCifrado);

        byte[] textoPlano = new byte[cifrado.Length];
        byte[] clave = DerivarClave(contrasena, sal);
        try
        {
            using var aes = new AesGcm(clave, TamTag);
            // Decrypt verifica el tag ANTES de dar por bueno el resultado.
            // Si no coincide lanza AuthenticationTagMismatchException (se captura en Main)
            // y textoPlano queda a ceros: nunca se escribe en disco.
            aes.Decrypt(nonce, cifrado, tag, textoPlano, cabecera);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(clave);
        }

        // 3) Sólo llegamos aquí si la integridad es correcta.
        File.WriteAllBytes(rutaSalida, textoPlano);
        CryptographicOperations.ZeroMemory(textoPlano);
    }

    // ========================================================================
    //  Utilidades
    // ========================================================================

    /// <summary>PBKDF2-HMAC-SHA256, 600.000 iteraciones, 32 bytes de salida (AES-256).</summary>
    private static byte[] DerivarClave(string contrasena, ReadOnlySpan<byte> sal)
    {
        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(contrasena),
            sal,
            Iteraciones,
            HashAlgorithmName.SHA256,
            TamClave);
    }

    private static byte[] ConstruirCabecera()
    {
        byte[] cab = new byte[TamCabecera];
        Firma.CopyTo(cab, 0);
        cab[TamFirma] = Version;
        return cab;
    }

    private static void MostrarUso()
    {
        Console.WriteLine("Uso:");
        Console.WriteLine("  CajaFuerte cifrar    <fichero_entrada.txt> <fichero_salida.caja> <contraseña>");
        Console.WriteLine("  CajaFuerte descifrar <fichero_salida.caja> <fichero_recuperado>  <contraseña>");
    }
}

/// <summary>El fichero no respeta la estructura del formato .caja.</summary>
public sealed class FormatoInvalidoException(string mensaje) : Exception(mensaje);
