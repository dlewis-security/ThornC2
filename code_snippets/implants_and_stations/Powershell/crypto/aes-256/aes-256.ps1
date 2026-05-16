Class Crypto {
	[string] enc($plaintext) {
		$key = [Text.Encoding]::UTF8.GetBytes('{{KEY}}')
		$iv = [Text.Encoding]::UTF8.GetBytes('{{IV}}')
		
		$AesManaged = New-Object "System.Security.Cryptography.AesCryptoServiceProvider"
		$AesManaged.Key = $key
		$AesManaged.IV = $iv
		$AesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
		$AesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$Encryptor = $AesManaged.CreateEncryptor()
		$MemoryStream = New-Object System.IO.MemoryStream
		$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $Encryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
		$CryptoStream.Write([System.Text.Encoding]::UTF8.GetBytes($plainText), 0, [System.Text.Encoding]::UTF8.GetByteCount($plainText))
		$CryptoStream.FlushFinalBlock()
		$CipherText = $MemoryStream.ToArray()
		$MemoryStream.Close()
		$CryptoStream.Close()
		$AesManaged.Clear()
		$ciphertext = [System.Convert]::ToBase64String($CipherText)
		return $CipherText
	}
	
	[string] dec($ciphertext) {
		$key = [Text.Encoding]::UTF8.GetBytes('{{KEY}}')
		$iv = [Text.Encoding]::UTF8.GetBytes('{{IV}}')
		
		$AesManaged = New-Object "System.Security.Cryptography.AesCryptoServiceProvider"
		$AesManaged.Key = $key
		$AesManaged.IV = $iv
		$AesManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
		$AesManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
		$Decryptor = $AesManaged.CreateDecryptor()
		$CipherBytes = [System.Convert]::FromBase64String($ciphertext)
		$MemoryStream = New-Object System.IO.MemoryStream
		$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream, $Decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
		$CryptoStream.Write($CipherBytes, 0, $CipherBytes.Length)
		$CryptoStream.FlushFinalBlock()
		$PlainText = [System.Text.Encoding]::UTF8.GetString($MemoryStream.ToArray())
		$MemoryStream.Close()
		$CryptoStream.Close()
		$AesManaged.Clear()
		return $PlainText
	}
}
