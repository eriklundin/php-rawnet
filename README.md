# php-rawnet

php-rawnet is a PHP extension designed to expose the raw (as-near-as-possible) network functions in Linux systems. The stream library in php does not provide full control over
none-blocking SSL sockets and this extension is designed to fill that gap.

## Examples

###### Simple SSL connection

```
$rn = rawnet_init();

if(is_string(($ret = rawnet_connect($rn, 'www.google.se', 443))))
     die($ret);

if(is_string(($ret = rawnet_ssl_connect($rn, NULL, NULL, '/etc/pki/tls/certs/ca-bundle.crt'))))
    die($ret);

if(($ret = rawnet_write($rn, "GET /\r\n\r\n")) === FALSE)
    die("Unable to write to socket");

echo "Wrote $ret bytes\n";

while(($ret = rawnet_read($rn, 4096)) !== FALSE) {
    var_dump($ret);
}

rawnet_ssl_close($rn);
rawnet_close($rn);
```

###### A more advanced server example

```
define('CLIENT_STATUS_ACCEPT',      1);
define('CLIENT_STATUS_SSLACCEPT',   2);

$rn = rawnet_init();
$ret = rawnet_listen($rn, 8080, 10);
$ret = rawnet_ssl_listen(
        $rn,
        '/tmp/localhost.crt',
        '/tmp/localhost.key',
        '/tmp/testca.crt',
        TRUE
);

rawnet_set_blocking($rn, FALSE);
$clients = array();

while(TRUE) {

    $a_read = array($rn);
    $a_write = array();
    $a_except = array();

    foreach($clients as $c) {
        $a_read[] = $c['res'];
        if($c['outbuf'] != '')
            $a_write[] = $c['res'];
    }

    if(rawnet_select($a_read, $a_write, $a_except, 1) > 0) {

        if(in_array($rn, $a_read)) {
            $newcon = rawnet_accept($rn);
            if(is_resource($newcon)) {
                $info = rawnet_getinfo($newcon);
                echo "New client connection from {$info['hostname']}:{$info['port']}\n";
                rawnet_set_blocking($newcon, FALSE);
                $clients[] = array(
                    'res' => $newcon,
                    'status' => CLIENT_STATUS_ACCEPT,
                    'outbuf' => ''
                );
            }
	}

	foreach($clients as $n => $c) {

            if(in_array($c['res'], $a_read)) {

                if($c['status'] == CLIENT_STATUS_ACCEPT) {

                        $ret = rawnet_ssl_accept($c['res'], TRUE);
                        if($ret === TRUE) {
                            // Success
                            $clients[$n]['status'] = CLIENT_STATUS_SSLACCEPT;
                            echo "Accepted client SSL\n";
                            $cinfo = rawnet_getinfo($c['res']);
                            var_dump($cinfo);
                        } else if($ret === FALSE) {
                            // Try again
                        } else {
                            echo "Unable to SSL-accept client: $ret\n";
                            rawnet_close($c['res']);
                            unset($clients[$n]);
                        }

                } else if($c['status'] == CLIENT_STATUS_SSLACCEPT) {
                        $ret = rawnet_read($c['res'], 2048);
                        echo "Received client data:\n";
                        var_dump($ret);
                        $clients[$n]['outbuf'] = "Hello world\n";
                }

            }

            if(in_array($c['res'], $a_write)) {
                $ret = rawnet_write($c['res'], $c['outbuf']);
                if(is_int($ret)) {
                    echo "Wrote $ret bytes\n";
                    $clients[$n]['outbuf'] = substr($c['outbuf'], $ret);
                    rawnet_ssl_close($c['res']);
                    rawnet_close($c['res']);
                }
            }
	}
    }
}
```

