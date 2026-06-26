param(
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8080
)

if ($HostName -notin @("127.0.0.1", "localhost")) {
    throw "Only loopback targets are allowed for this fixture."
}

$client = [System.Net.Sockets.TcpClient]::new()
try {
    $async = $client.BeginConnect($HostName, $Port, $null, $null)
    [void]$async.AsyncWaitHandle.WaitOne(1000)
    if ($client.Connected) {
        $client.EndConnect($async)
    }
} catch {
    # A refused loopback connection is acceptable; the attempt is the signal.
} finally {
    $client.Close()
}
