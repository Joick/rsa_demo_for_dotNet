using Newtonsoft.Json;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace RSA.Web.Helpers
{
    public static class RSAHelper
    {
        private static RSACryptoServiceProvider _privateKeyRsaProvider = null;
        private static RSACryptoServiceProvider _publicKeyRsaProvider = null;

        private static RSAKeys _rsakeys = new RSAKeys();

        // 设置[公钥私钥]文件路径
        private static readonly string privateKeyPath = AppDomain.CurrentDomain.BaseDirectory + "\\Resources\\rsa_key.pri";
        private static readonly string publicKeyPath = AppDomain.CurrentDomain.BaseDirectory + "\\Resources\\rsa_key.pub";

        public static string GetPublicKey()
        {
            InitRSAKey();

            return _rsakeys.JPublicKey;
        }

        #region initialization

        /// <summary>
        /// 初始化RSA对象
        /// </summary>
        private static void InitRSAKey()
        {
            if (!IsGenerated())
            {
                GenerateRSAKey();
                return;
            }

            _privateKeyRsaProvider = _publicKeyRsaProvider = new RSACryptoServiceProvider();

            _privateKeyRsaProvider.Clear();
            _publicKeyRsaProvider.Clear();

            _privateKeyRsaProvider.FromXmlString(_rsakeys.PrivateKey);

            _publicKeyRsaProvider.FromXmlString(_rsakeys.PublicKey);
        }

        /// <summary>
        /// 检查密钥是否已生成
        /// </summary>
        /// <returns></returns>
        private static bool IsGenerated()
        {
            if (!File.Exists(privateKeyPath) || !File.Exists(publicKeyPath))
            {
                return false;
            }

            if (_privateKeyRsaProvider == null || _publicKeyRsaProvider == null)
            {
                return false;
            }

            foreach (var i in _rsakeys.GetType().GetProperties())
            {
                if (i.GetValue(_rsakeys) == null)
                {
                    return false;
                }
            }

            return true;

        }

        /// <summary>
        /// 创建RSA密钥对
        /// </summary>
        private static void GenerateRSAKey()
        {
            _privateKeyRsaProvider = _publicKeyRsaProvider = null;

            //创建RSA对象
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();

            _privateKeyRsaProvider = rsa;

            //生成RSA[公钥私钥]
            _rsakeys = new RSAKeys();
            _rsakeys.GenerateKeys(rsa);

            //将密钥写入指定路径
            File.WriteAllText(privateKeyPath, _rsakeys.PrivateKey);
            File.WriteAllText(publicKeyPath, _rsakeys.PublicKey);

            // 设置公钥RSA加密对象(不可转成私钥对象)
            _publicKeyRsaProvider = new RSACryptoServiceProvider();
            _publicKeyRsaProvider.FromXmlString(_rsakeys.PublicKey);
        }

        #endregion

        #region 加密&解密

        /// <summary>
        /// 解密
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="text"></param>
        /// <returns></returns>
        public static T Decrypt<T>(string text)
        {
            string decryptTxt = Decrypt(text);
            return JsonConvert.DeserializeObject<T>(decryptTxt);
        }

        /// <summary>
        /// 解密
        /// </summary>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public static string Decrypt(string cipherText)
        {
            if (_privateKeyRsaProvider == null)
            {
                InitRSAKey();
            }

            // 长度小于 128 的解密操作
            if (cipherText.Length <= 128)
            {
                return Encoding.UTF8.GetString(_privateKeyRsaProvider.Decrypt(Convert.FromBase64String(cipherText), false));
            }

            // 长度大于128的解密方法
            var rsaProvider = _privateKeyRsaProvider;
            var inputBytes = Convert.FromBase64String(cipherText);

            int bufferSize = rsaProvider.KeySize / 8;
            var buffer = new byte[bufferSize];

            using (MemoryStream inputStream = new MemoryStream(inputBytes),
                outputStream = new MemoryStream())
            {
                while (true)
                {
                    int readSize = inputStream.Read(buffer, 0, bufferSize);
                    if (readSize <= 0)
                    {
                        break;
                    }

                    var temp = new byte[readSize];

                    Array.Copy(buffer, 0, temp, 0, readSize);

                    var rawBytes = rsaProvider.Decrypt(temp, false);

                    outputStream.Write(rawBytes, 0, rawBytes.Length);
                }

                return Encoding.UTF8.GetString(outputStream.ToArray());
            }

        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="model">加密数据源</param>
        /// <param name="isPublicKey">是否使用公钥加密</param>
        /// <returns></returns>
        public static string EncryptObject<T>(T model, bool isPublicKey = false)
        {
            string json = JsonConvert.SerializeObject(model);
            return Encrypt(json, isPublicKey);
        }

        /// <summary>
        /// 加密
        /// </summary>
        /// <param name="text">加密字符串</param>
        /// <param name="isPublicKey">是否使用公钥加密</param>
        /// <returns></returns>
        public static string Encrypt(string text, bool isPublicKey = false)
        {
            if (_publicKeyRsaProvider == null || _privateKeyRsaProvider == null)
            {
                InitRSAKey();
            }

            RSACryptoServiceProvider provider = isPublicKey ? _publicKeyRsaProvider : _privateKeyRsaProvider;

            return EncryptBase(provider, text);
        }

        /// <summary>
        /// 加密基本方法
        /// </summary>
        /// <param name="provider"></param>
        /// <param name="text"></param>
        /// <returns></returns>
        private static string EncryptBase(RSACryptoServiceProvider provider, string text)
        {
            if (text.Length <= 128)
            {
                return Convert.ToBase64String(provider.Encrypt(Encoding.UTF8.GetBytes(text), false));
            }

            // 有含义的字符串转化为字节流
            var inputBytes = Encoding.UTF8.GetBytes(text);

            // 单块最大长度
            int bufferSize = (provider.KeySize / 8) - 11;

            var buffer = new byte[bufferSize];

            using (MemoryStream inputStream = new MemoryStream(inputBytes),
                 outputStream = new MemoryStream())
            {
                while (true)
                {
                    //分段加密
                    int readSize = inputStream.Read(buffer, 0, bufferSize);

                    if (readSize <= 0)
                    {
                        break;
                    }

                    var temp = new byte[readSize];

                    Array.Copy(buffer, 0, temp, 0, readSize);

                    var encryptedBytes = provider.Encrypt(temp, false);

                    outputStream.Write(encryptedBytes, 0, encryptedBytes.Length);

                }

                return Convert.ToBase64String(outputStream.ToArray());//转化为字节流方便传输
            }
        }

        /// <summary>
        /// 加签
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static string GenerateSign<T>(T dataObj)//(string data)
        {
            string data = JsonConvert.SerializeObject(dataObj);

            byte[] bt = Encoding.UTF8.GetBytes(data);
            var sha256 = new SHA256CryptoServiceProvider();

            byte[] rgbHash = sha256.ComputeHash(bt);

            RSAPKCS1SignatureFormatter formatter = new RSAPKCS1SignatureFormatter(_privateKeyRsaProvider);

            formatter.SetHashAlgorithm("SHA256");

            byte[] inArray = formatter.CreateSignature(rgbHash);

            return Convert.ToBase64String(inArray);
        }

        #endregion

        #region 根据base64格式生成RSA密钥

        /// <summary>
        /// 根据base64格式私钥生成RSA对象
        /// </summary>
        /// <param name="privateKey"></param>
        /// <returns></returns>
        private static RSACryptoServiceProvider CreateRsaProviderFromPrivateKey(string privateKey)
        {
            var privateKeyBits = Convert.FromBase64String(privateKey);

            var RSA = new RSACryptoServiceProvider();
            var RSAparams = new RSAParameters();

            using (BinaryReader binr = new BinaryReader(new MemoryStream(privateKeyBits)))
            {
                byte bt = 0;
                ushort twobytes = 0;

                twobytes = binr.ReadUInt16();

                if (twobytes == 0x8130)
                {
                    binr.ReadByte();
                }
                else if (twobytes == 0x8230)
                {
                    binr.ReadInt16();
                }
                else
                {
                    throw new Exception("Unexpected value read binr.ReadUInt16()");
                }

                twobytes = binr.ReadUInt16();

                if (twobytes != 0x0102)
                {
                    throw new Exception("Unexpected version");
                }

                bt = binr.ReadByte();

                if (bt != 0x00)
                {
                    throw new Exception("Unexpected value read binr.ReadByte()");
                }

                RSAparams.Modulus = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.Exponent = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.D = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.P = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.Q = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.DP = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.DQ = binr.ReadBytes(GetIntegerSize(binr));
                RSAparams.InverseQ = binr.ReadBytes(GetIntegerSize(binr));
            }

            RSA.ImportParameters(RSAparams);

            return RSA;
        }

        private static int GetIntegerSize(BinaryReader binr)
        {
            byte bt = 0;
            byte lowbyte = 0x00;
            byte highbyte = 0x00;
            int count = 0;

            bt = binr.ReadByte();

            if (bt != 0x02)
                return 0;

            bt = binr.ReadByte();

            if (bt == 0x81)
            {
                count = binr.ReadByte();
            }
            else if (bt == 0x82)
            {
                highbyte = binr.ReadByte();
                lowbyte = binr.ReadByte();

                byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                count = BitConverter.ToInt32(modint, 0);
            }
            else
            {
                count = bt;
            }

            while (binr.ReadByte() == 0x00)
            {
                count -= 1;
            }

            binr.BaseStream.Seek(-1, SeekOrigin.Current);

            return count;
        }

        /// <summary>
        /// 根据base64格式公钥生成RSA对象
        /// </summary>
        /// <param name="publicKeyString"></param>
        /// <returns></returns>
        private static RSACryptoServiceProvider CreateRsaProviderFromPublicKey(string publicKeyString)
        {
            // encoded OID sequence for  PKCS #1 rsaEncryption szOID_RSA_RSA = "1.2.840.113549.1.1.1"
            byte[] SeqOID = { 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
            byte[] x509key;
            byte[] seq = new byte[15];
            int x509size;

            x509key = Convert.FromBase64String(publicKeyString);
            x509size = x509key.Length;

            // Set up stream to read the asn.1 encoded SubjectPublicKeyInfo blob
            using (MemoryStream mem = new MemoryStream(x509key))
            {
                using (BinaryReader binr = new BinaryReader(mem))  //wrap Memory Stream with BinaryReader for easy reading
                {
                    byte bt = 0;
                    ushort twobytes = 0;

                    twobytes = binr.ReadUInt16();

                    // data read as little endian order (actual data order for Sequence is 30 81)
                    if (twobytes == 0x8130)
                    {
                        // advance 1 byte
                        binr.ReadByte();
                    }
                    else if (twobytes == 0x8230)
                    {

                        // advance 2 bytes
                        binr.ReadInt16();
                    }
                    else
                    {
                        return null;
                    }

                    // read the Sequence OID
                    seq = binr.ReadBytes(15);

                    // make sure Sequence for OID is correct
                    if (!CompareBytearrays(seq, SeqOID))
                    {
                        return null;
                    }

                    twobytes = binr.ReadUInt16();

                    // data read as little endian order (actual data order for Bit String is 03 81)
                    if (twobytes == 0x8103)
                    {
                        // advance 1 byte
                        binr.ReadByte();
                    }
                    else if (twobytes == 0x8203)
                    {
                        // advance 2 bytes
                        binr.ReadInt16();
                    }
                    else
                    {
                        return null;
                    }

                    bt = binr.ReadByte();
                    if (bt != 0x00)
                    {
                        // expect null byte next
                        return null;
                    }

                    twobytes = binr.ReadUInt16();

                    // data read as little endian order (actual data order for Sequence is 30 81)
                    if (twobytes == 0x8130)
                    {
                        // advance 1 byte
                        binr.ReadByte();
                    }
                    else if (twobytes == 0x8230)
                    {
                        // advance 2 bytes
                        binr.ReadInt16();
                    }
                    else
                    {
                        return null;
                    }

                    twobytes = binr.ReadUInt16();

                    byte lowbyte = 0x00;
                    byte highbyte = 0x00;

                    //data read as little endian order (actual data order for Integer is 02 81)
                    if (twobytes == 0x8102)
                    {
                        // read next bytes which is bytes in modulus
                        lowbyte = binr.ReadByte();
                    }
                    else if (twobytes == 0x8202)
                    {
                        // advance 2 bytes
                        highbyte = binr.ReadByte();
                        lowbyte = binr.ReadByte();
                    }
                    else
                    {
                        return null;
                    }

                    // reverse byte order since asn.1 key uses big endian order
                    byte[] modint = { lowbyte, highbyte, 0x00, 0x00 };
                    int modsize = BitConverter.ToInt32(modint, 0);

                    int firstbyte = binr.PeekChar();
                    if (firstbyte == 0x00)
                    {
                        // if first byte (highest order) of modulus is zero, don't include it
                        // skip this null byte
                        binr.ReadByte();

                        // reduce modulus buffer size by 1
                        modsize -= 1;
                    }

                    // read the modulus bytes
                    byte[] modulus = binr.ReadBytes(modsize);

                    // expect an Integer for the exponent data
                    if (binr.ReadByte() != 0x02)
                    {
                        return null;
                    }

                    // should only need one byte for actual exponent data (for all useful values)
                    int expbytes = (int)binr.ReadByte();
                    byte[] exponent = binr.ReadBytes(expbytes);

                    // create RSACryptoServiceProvider instance and initialize with public key 
                    RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
                    RSAParameters RSAKeyInfo = new RSAParameters();

                    RSAKeyInfo.Modulus = modulus;
                    RSAKeyInfo.Exponent = exponent;

                    RSA.ImportParameters(RSAKeyInfo);

                    return RSA;
                }
            }
        }

        private static bool CompareBytearrays(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
            {
                return false;
            }

            int i = 0;

            foreach (byte c in a)
            {
                if (c != b[i])
                {
                    return false;
                }

                i++;
            }

            return true;
        }

        #endregion

        #region dotNet 2 Java

        /// <summary>
        /// (使用java格式密钥)加密
        /// </summary>
        /// <param name="data">源数据</param>
        /// <param name="isPublicKey">是否使用公钥加密</param>
        /// <returns></returns>
        public static string JEncrypt(string data, bool isPublicKey = true)
        {
            string key = null;

            RsaKeyParameters keyParam = null;

            if (isPublicKey)
            {
                key = _rsakeys.JPublicKey;
                keyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(key));
            }
            else
            {
                key = _rsakeys.JPrivateKey;
                keyParam = (RsaKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(key));
            }

            byte[] cipherbytes = Encoding.UTF8.GetBytes(data);

            RsaEngine rsa = new RsaEngine();

            // 参数true表示加密,false表示解密
            rsa.Init(true, keyParam);

            cipherbytes = rsa.ProcessBlock(cipherbytes, 0, cipherbytes.Length);

            return Convert.ToBase64String(cipherbytes);

        }

        /// <summary>
        /// (使用java格式密钥)加密
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="dataObj"></param>
        /// <param name="isPublicKey"></param>
        /// <returns></returns>
        public static string JEncryptObject<T>(T dataObj, bool isPublicKey = true)
        {
            string data = JsonConvert.SerializeObject(dataObj);
            return JEncrypt(data, isPublicKey);
        }

        /// <summary>
        /// (使用java格式密钥)解密
        /// </summary>
        /// <param name="data">密文</param>
        /// <param name="isPrivateKey">是否使用私钥解密</param>
        /// <returns></returns>
        public static string JDecrypt(string data, bool isPrivateKey = true)
        {
            string key = null;

            RsaKeyParameters keyParam = null;

            if (isPrivateKey)
            {
                key = _rsakeys.JPrivateKey;
                keyParam = (RsaKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(key));
            }
            else
            {
                key = _rsakeys.JPublicKey;
                keyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(key));
            }

            byte[] cipherbytes = Convert.FromBase64String(data);

            RsaEngine rsa = new RsaEngine();

            rsa.Init(false, keyParam);

            cipherbytes = rsa.ProcessBlock(cipherbytes, 0, cipherbytes.Length);

            return Encoding.UTF8.GetString(cipherbytes);
        }

        /// <summary>
        /// (使用java格式密钥)解密
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="data"></param>
        /// <param name="isPrivateKey"></param>
        /// <returns></returns>
        public static T JDecryptObject<T>(string data, bool isPrivateKey = true)
        {
            string dataObj = JDecrypt(data, isPrivateKey);
            return JsonConvert.DeserializeObject<T>(dataObj);
        }

        /// <summary>
        /// RSA私钥格式转换，java->.net
        /// </summary>
        /// <param name="privateKey">java生成的RSA私钥</param>
        /// <returns></returns>
        private static string RSAPrivateKeyJava2DotNet(string privateKey)
        {
            RsaPrivateCrtKeyParameters privateKeyParam = (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(Convert.FromBase64String(privateKey));

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent><P>{2}</P><Q>{3}</Q><DP>{4}</DP><DQ>{5}</DQ><InverseQ>{6}</InverseQ><D>{7}</D></RSAKeyValue>",
                Convert.ToBase64String(privateKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.PublicExponent.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.P.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.Q.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.DP.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.DQ.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.QInv.ToByteArrayUnsigned()),
                Convert.ToBase64String(privateKeyParam.Exponent.ToByteArrayUnsigned()));
        }

        /// <summary>
        /// RSA私钥格式转换，.net->java
        /// </summary>
        /// <param name="privateKey">.net生成的私钥</param>
        /// <returns></returns>
        private static string RSAPrivateKeyDotNet2Java(string privateKey)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(privateKey);

            BigInteger m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            BigInteger exp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));
            BigInteger d = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("D")[0].InnerText));
            BigInteger p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("P")[0].InnerText));
            BigInteger q = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Q")[0].InnerText));
            BigInteger dp = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DP")[0].InnerText));
            BigInteger dq = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("DQ")[0].InnerText));
            BigInteger qinv = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("InverseQ")[0].InnerText));

            RsaPrivateCrtKeyParameters privateKeyParam = new RsaPrivateCrtKeyParameters(m, exp, d, p, q, dp, dq, qinv);

            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKeyParam);

            byte[] serializedPrivateBytes = privateKeyInfo.ToAsn1Object().GetEncoded();

            return Convert.ToBase64String(serializedPrivateBytes);
        }

        /// <summary>
        /// RSA公钥格式转换，java->.net
        /// </summary>
        /// <param name="publicKey">java生成的公钥</param>
        /// <returns></returns>
        private static string RSAPublicKeyJava2DotNet(string publicKey)
        {
            RsaKeyParameters publicKeyParam = (RsaKeyParameters)PublicKeyFactory.CreateKey(Convert.FromBase64String(publicKey));

            return string.Format("<RSAKeyValue><Modulus>{0}</Modulus><Exponent>{1}</Exponent></RSAKeyValue>",
                Convert.ToBase64String(publicKeyParam.Modulus.ToByteArrayUnsigned()),
                Convert.ToBase64String(publicKeyParam.Exponent.ToByteArrayUnsigned()));
        }

        /// <summary>
        /// RSA公钥格式转换，.net->java
        /// </summary>
        /// <param name="publicKey">.net生成的公钥</param>
        /// <returns></returns>
        private static string RSAPublicKeyDotNet2Java(string publicKey)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(publicKey);

            BigInteger m = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Modulus")[0].InnerText));
            BigInteger p = new BigInteger(1, Convert.FromBase64String(doc.DocumentElement.GetElementsByTagName("Exponent")[0].InnerText));

            RsaKeyParameters pub = new RsaKeyParameters(false, m, p);

            SubjectPublicKeyInfo publicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);

            byte[] serializedPublicBytes = publicKeyInfo.ToAsn1Object().GetDerEncoded();

            return Convert.ToBase64String(serializedPublicBytes);
        }

        #endregion

        #region dataModel
        private class RSAKeys
        {
            public string PublicKey { get; set; }
            public string PrivateKey { get; set; }
            public string JPublicKey { get; set; }
            public string JPrivateKey { get; set; }

            internal void GenerateKeys(RSACryptoServiceProvider rsa)
            {
                PrivateKey = rsa.ToXmlString(true);
                PublicKey = rsa.ToXmlString(false);

                JPublicKey = RSAHelper.RSAPublicKeyDotNet2Java(PublicKey);
                JPrivateKey = RSAHelper.RSAPrivateKeyDotNet2Java(PrivateKey);
            }
        }

        #endregion
    }


}