function envkey($user) {
	$stringAsStream = [System.IO.MemoryStream]::new()
	$writer = [System.IO.StreamWriter]::new($stringAsStream)
	$writer.write("$user")
	$writer.Flush()
	$stringAsStream.Position = 0
	$usermd5 = Get-FileHash -InputStream $stringAsStream -Algorithm MD5
    if ($usermd5.Hash -eq "{{USERNAME}}") {
        return [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{{STATION}}"))
    } else {
        Exit
    }
}
