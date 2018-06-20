using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Net.Configuration;
using System.Configuration;
using System.Collections.Specialized;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using static System.Net.Mime.MediaTypeNames;
using System.Reflection;

namespace UDPListener
{
    class Program
    {
        private const int listenPort = 11000;
        static UdpClient listener = new UdpClient(listenPort);
        static IPEndPoint groupEP = new IPEndPoint(IPAddress.Any, listenPort);
        static string EncryptionKey = ConfigurationManager.AppSettings.Get("EncryptionKey");
        static string InitVector = ConfigurationManager.AppSettings.Get("InitVector");
        static byte[] bEncryptionKey = StringToByteArray(EncryptionKey, 16);
        //static byte[] bInitVector = StringToByteArray(InitVector, 16);
        static void Main(string[] args)
        {
            Console.WriteLine("UDP Listener " + Assembly.GetExecutingAssembly().GetName().Version);
            Console.WriteLine("Waiting for broadcast");
            Console.WriteLine("AES Encryption key: " + EncryptionKey);
            //Console.WriteLine("Init Vector: " + InitVector);
            Console.WriteLine("Listening Port: " + listenPort);
            while (true)
            {
                Listen();
            }
        }

        public static void Listen()
        {
            //UdpClient listener = new UdpClient(listenPort);
            //IPEndPoint groupEP = new IPEndPoint(IPAddress.Any, listenPort);
            string received_data;
            byte[] receivedByteArray;
            byte[] decryptedByteArray;
            string decodedText = "";
            try
            {
                //Console.WriteLine("Waiting for broadcast");
                // this is the line of code that receives the broadcase message.
                // It calls the receive function from the object listener (class UdpClient)
                // It passes to listener the end point groupEP.
                // It puts the data from the broadcast message into the byte array
                // named receivedByteArray.
                receivedByteArray = listener.Receive(ref groupEP);
                int receivedByteArrayLength = receivedByteArray.Length;
                //get the session ID that was sent
                byte[] receivedSessionID = receivedByteArray.Skip(0).Take(4).ToArray();
                //get the IV that was sent
                byte[] receivedInitVector = receivedByteArray.Skip(4).Take(16).ToArray();
                //get the remainder 
                byte[] receivedEncrypted = receivedByteArray.Skip(20).Take(receivedByteArrayLength-20).ToArray();

                decryptedByteArray = Decrypt(receivedEncrypted, bEncryptionKey, receivedInitVector);
                received_data = Encoding.Default.GetString(decryptedByteArray);
                decodedText = Unzip(decryptedByteArray);

                Console.WriteLine(Environment.NewLine);
                Console.WriteLine(Environment.NewLine);
                Console.WriteLine("Received broadcast from {0}", groupEP.ToString() + " at " + DateTime.Now);
                Console.WriteLine("Bytes received: " + receivedByteArrayLength);
                Console.WriteLine("Session ID: " + ByteArrayToString(receivedSessionID));
                Console.WriteLine("Init Vector: " + ByteArrayToString(receivedInitVector));
                Console.WriteLine(decodedText);
            }
            catch (Exception ex)
            {
                Console.WriteLine(Environment.NewLine);
                Console.WriteLine(ex.ToString());
            }
        }
        public static string Unzip(byte[] zippedData)
        {
            int byteCount = zippedData.Length;

            using (var msi = new MemoryStream(zippedData))
            using (var mso = new MemoryStream())
            {
                using (var gs = new DeflateStream(msi, CompressionMode.Decompress))
                {
                    gs.CopyTo(mso);
                    //CopyTo(gs, mso);
                }

                //using (var gs = new GZipStream(msi, CompressionMode.Decompress))
                //{
                //    gs.CopyTo(mso);
                //    //CopyTo(gs, mso);
                //}

                return Encoding.UTF8.GetString(mso.ToArray());
            }
        }

        public static byte[] Decrypt(byte[] encryptedData, byte[] encKey, byte[] initVect)
        {
            try
            {
                using (AesCryptoServiceProvider aes = new AesCryptoServiceProvider { Key = encKey, IV = initVect, Padding = PaddingMode.PKCS7 })
                using (ICryptoTransform decryptor = aes.CreateDecryptor(encKey, initVect))
                using (MemoryStream ms = new MemoryStream(encryptedData))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    var decrypted = new byte[encryptedData.Length];
                    var bytesRead = cs.Read(decrypted, 0, encryptedData.Length);
                    return decrypted.Take(bytesRead).ToArray();
                }

            }catch(Exception ex)
            {
                Console.WriteLine(ex.Message);
                return null;
            }
        }

        public static string ByteArrayToString(byte[] ba)
        {
            return BitConverter.ToString(ba).Replace("-", "");
        }
        //private static readonly byte[] SALT = new byte[] { 0x26, 0xdc, 0xff, 0x00, 0xad, 0xed, 0x7a, 0xee }; //, 0xc5, 0xfe, 0x07, 0xaf, 0x4d, 0x08, 0x22, 0x3c };
        //private static readonly byte[] ENCKEY = new byte[] { 0x26, 0xdc, 0xff, 0x00, 0xad, 0xed, 0x7a, 0xee, 0xc5, 0xfe, 0x07, 0xaf, 0x4d, 0x08, 0x22, 0x3c, 0x26, 0xdc, 0xff, 0x00, 0xad, 0xed, 0x7a, 0xee, 0xc5, 0xfe, 0x07, 0xaf, 0x4d, 0x08, 0x22, 0x3c };
        //private static readonly byte[] INITVECTOR = new byte[] { 0x26, 0xdc, 0xff, 0x00, 0xad, 0xed, 0x7a, 0xee, 0xc5, 0xfe, 0x07, 0xaf, 0x4d, 0x08, 0x22, 0x3c };

        //private static byte[] CreateKey(string password, int keySize, byte[] salt)
        //{
        //    Rfc2898DeriveBytes derivedKey = new Rfc2898DeriveBytes(password, salt, 1000);
        //    return derivedKey.GetBytes(keySize >> 3);
        //}

        //public static byte[] Decrypt(byte[] encryptedData, byte[] encKey, byte[] initVect)
        //{
        //    byte[] decryptedData = new byte[encryptedData.Length];
        //    using (AesCryptoServiceProvider provider = new AesCryptoServiceProvider())
        //    {
        //        //provider.Key = CreateKey(password, provider.KeySize, encSalt); //by default keysize appears to be 256 bits
        //        provider.Key = encKey; //by default keysize appears to be 256 bits
        //        provider.IV = initVect;
        //        provider.Mode = CipherMode.CBC;
        //        provider.Padding = PaddingMode.PKCS7;
        //        using (MemoryStream memStream = new MemoryStream(encryptedData))
        //        {
        //            //byte[] iv = new byte[16];
        //            memStream.Read(provider.IV, 0, 16);
        //            using (ICryptoTransform decryptor = provider.CreateDecryptor(provider.Key, provider.IV))
        //            {
        //                using (CryptoStream cryptoStream = new CryptoStream(memStream, decryptor, CryptoStreamMode.Read))
        //                {
        //                    cryptoStream.Read(decryptedData, 0, decryptedData.Length);
        //                }
        //            }
        //        }
        //    }
        //    return decryptedData;
        //}
        public static byte[] StringToByteArray(string hex, int numberBase) //base 10 or 16
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), numberBase))
                             .ToArray();
        }

        //public static byte[] Decrypt(byte[] cipher, string password)
        //{
        //    MemoryStream memoryStream;
        //    CryptoStream cryptoStream;
        //    Aes aesCrypto = Aes.Create();
        //    Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(password, SALT);
        //    aesCrypto.Key = pdb.GetBytes(32);
        //    aesCrypto.IV = pdb.GetBytes(16);
        //    memoryStream = new MemoryStream();
        //    cryptoStream = new CryptoStream(memoryStream, aesCrypto.CreateDecryptor(), CryptoStreamMode.Write);
        //    cryptoStream.Write(cipher, 0, cipher.Length);
        //    cryptoStream.Close();
        //    return memoryStream.ToArray();
        //}

    }
}

