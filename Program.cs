using System;
using System.Net;
using System.Net.NetworkInformation;
using System.Windows.Forms;
using Oracle.ManagedDataAccess.Client;
using System.Security.Cryptography;
using System.Text;
using System.IO;
using System.Xml;
using System.Configuration;
using System.Linq;
namespace MachineDetails
{
    internal static class Program
    {
        private const string SECRET_KEY_ALGORITHM = "AES";
        private const string ENCRYPTION_ALGORITHM = "AES/CBC/PKCS7Padding";
        private const string SECRET_KEY = "YourSecretKey"; // Change this to your secret key

        public static string DecryptPassword(string encryptedPassword)
        {
            byte[] combined = Convert.FromBase64String(encryptedPassword);

            byte[] iv = new byte[16];
            byte[] encrypted = new byte[combined.Length - iv.Length];
            Array.Copy(combined, 0, iv, 0, iv.Length);
            Array.Copy(combined, iv.Length, encrypted, 0, encrypted.Length);

            using (var factory = new Rfc2898DeriveBytes(SECRET_KEY, Encoding.UTF8.GetBytes(SECRET_KEY), 65536, HashAlgorithmName.SHA256))
            {
                byte[] keyBytes = factory.GetBytes(256 / 8);
                using (var secret = new AesCryptoServiceProvider())
                {
                    secret.Key = keyBytes;
                    secret.Mode = CipherMode.CBC;
                    secret.Padding = PaddingMode.PKCS7;
                    using (var decryptor = secret.CreateDecryptor(secret.Key, iv))
                    {
                        byte[] decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
                        return Encoding.UTF8.GetString(decrypted);
                    }
                }
            }
        }
        
        static void LogExceptionToFile(Exception ex)
        {
            string logFilePath = "error.log";

            // Write the exception details to the log file
            using (StreamWriter writer = new StreamWriter(logFilePath, append: false))
            {
                writer.WriteLine($"Timestamp: {DateTime.Now}");
                writer.WriteLine($"Exception Type: {ex.GetType().FullName}");
                writer.WriteLine($"Message: {ex.Message}");
                writer.WriteLine($"Stack Trace:\n{ex.StackTrace}");
                writer.WriteLine(new string('-', 50));
                writer.WriteLine(); // Add an empty line for readability
            }
        }
       


        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        [STAThread]
        static void Main()
        {

            string DBUsername;
            string DBPassword;
            string ServiceName;
            string HostIP;
            string DBTableName;
            string hostName;
            string IPv6 = null;
            IPHostEntry ipEntry;
            IPAddress[] addr;
            string IPv4 =null;
            string WindowsUserName;
            String timeStamp;
            string MacAddr;

            try
            {

                hostName = System.Net.Dns.GetHostName();
                WindowsUserName = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                ipEntry = System.Net.Dns.GetHostEntry(hostName);
                addr = ipEntry.AddressList;
                // Get the IP addresses associated with the host
                IPAddress[] addresses = Dns.GetHostAddresses(hostName);
                IPAddress[] ipv4Addresses = addresses.Where(address => address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork).ToArray();
               
                // Iterate through the AddressList to find IPv6 addresses
                foreach (var address in addr)
                {
                    if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) // IPv6
                    {
                        IPv6 = address.ToString();
                    }
                }

               

                MacAddr = "";
                foreach (NetworkInterface n in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (n.OperationalStatus == OperationalStatus.Up)
                    {
                        MacAddr += n.GetPhysicalAddress().ToString();
                        break;
                    }
                }
                

                DBTableName = ConfigurationManager.AppSettings["DBTableName"];
                DBUsername = ConfigurationManager.AppSettings["DBUsername"];
                string DBPassword_Encrypted = ConfigurationManager.AppSettings["DBPassword"];
                DBPassword = DecryptPassword(DBPassword_Encrypted);
                HostIP = ConfigurationManager.AppSettings["HostIP"];
                ServiceName = ConfigurationManager.AppSettings["ServiceName"];
                timeStamp = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                
                //string connectionString = "Data Source=" + ServiceName + ";Initial Catalog=" + DatabaseName + ";User Id=" + DBUsername + ";Password=" + DBPassword + ";";

                string connectionString = @"Data Source=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST="+ HostIP +")(PORT=1521))(CONNECT_DATA=(SERVICE_NAME=" + ServiceName + ")));User Id=" + DBUsername +";Password=" + DBPassword + ";";
                // Parse the timestamp string using DateTime.TryParseExact

                using (OracleConnection con = new OracleConnection(connectionString))
                {
                    con.Open();
                    foreach (IPAddress address in ipv4Addresses)
                    {
                        string insertQuery = "INSERT INTO " + DBTableName + " (HoSTNAME, WINDOWSUSERNAME, MACADDR, IPV4, IPV6, TIMESTAMP) VALUES " +
                            "(:HOSTNAME, :WINDOWSUSERNAME, :MACADDR, :IPV4, :IPV6, :TIMESTAMP)";

                        OracleCommand insertCommand = new OracleCommand(insertQuery, con);
                        int indexOfBackslash = WindowsUserName.LastIndexOf('\\');

                        if (indexOfBackslash != -1 && indexOfBackslash < WindowsUserName.Length - 1)
                        {
                            WindowsUserName = WindowsUserName.Substring(indexOfBackslash + 1);
                        }

                        insertCommand.Parameters.Add("HOSTNAME", OracleDbType.Varchar2).Value = hostName;
                        insertCommand.Parameters.Add("WINDOWSUSERNAME", OracleDbType.Varchar2).Value = WindowsUserName;
                        insertCommand.Parameters.Add("MACADDR", OracleDbType.Varchar2).Value = MacAddr;
                        insertCommand.Parameters.Add("IPV4", OracleDbType.Varchar2).Value = address;
                        insertCommand.Parameters.Add("IPV6", OracleDbType.Varchar2).Value = IPv6;
                        insertCommand.Parameters.Add("TIMESTAMP", OracleDbType.Varchar2).Value = timeStamp;

                        insertCommand.ExecuteNonQuery();
                    }
                    con.Close();
                }


               






            }
            catch (Exception ex)
            {
                LogExceptionToFile(ex);
                
            }
        }
    }
    
}
