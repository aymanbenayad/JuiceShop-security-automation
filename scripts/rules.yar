import "hash"
import "math"

rule XSSPayload {
    meta:
        description = "Détecte les charges utiles XSS courantes dans les fichiers"
        severity = "High"
        author = "owasp"
        date = "2025-05-15"
    strings:
        $xss1 = "<script>" nocase wide ascii
        $xss2 = "alert(" nocase wide ascii
        $xss3 = "document.cookie" nocase wide ascii
        $xss4 = "onerror=" nocase wide ascii
        $xss5 = "javascript:" nocase wide ascii
        $xss6 = "onload=" nocase wide ascii
        $xss7 = "eval(" nocase wide ascii
        $xss8 = "fromCharCode" nocase wide ascii
        $xss9 = "String.fromCharCode" nocase wide ascii
        $xss10 = "\\x" nocase wide ascii
        $obfuscated1 = /eval\s*\(/ nocase wide ascii
        $obfuscated2 = /setTimeout\s*\(/ nocase wide ascii
        $obfuscated3 = /\\u00[0-9a-f]{2}/ nocase wide ascii
    condition:
        3 of ($xss*) or any of ($obfuscated*)
}

rule SQLInjection {
    meta:
        description = "Détecte les modèles d'injection SQL"
        severity = "Critical"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $sql1 = "SELECT " nocase wide ascii
        $sql2 = "UNION " nocase wide ascii
        $sql3 = "INSERT " nocase wide ascii
        $sql4 = "UPDATE " nocase wide ascii
        $sql5 = "DELETE " nocase wide ascii
        $sql6 = "DROP " nocase wide ascii
        $sql7 = "EXEC " nocase wide ascii
        $sql8 = "'" nocase wide ascii
        $sql9 = "--" nocase wide ascii
        $sql10 = ";" nocase wide ascii
        $sql11 = "/*" nocase wide ascii
        $sql12 = "1=1" nocase wide ascii
        $sql13 = "OR 1=" nocase wide ascii
        $sql14 = "SLEEP(" nocase wide ascii
        $sql15 = "BENCHMARK(" nocase wide ascii
        $sql16 = "WAITFOR DELAY" nocase wide ascii
        $escape = "\\'" nocase wide ascii
    condition:
        (4 of ($sql*)) and not $escape
}

rule CommandInjection {
    meta:
        description = "Détecte les modèles d'injection de commandes système"
        severity = "Critical"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $cmd1 = ";" nocase wide ascii
        $cmd2 = "|" nocase wide ascii
        $cmd3 = "&&" nocase wide ascii
        $cmd4 = "||" nocase wide ascii
        $cmd5 = "`" nocase wide ascii
        $cmd6 = "$(" nocase wide ascii
        $cmd7 = "system(" nocase wide ascii
        $cmd8 = "exec(" nocase wide ascii
        $cmd9 = "shell_exec(" nocase wide ascii
        $cmd10 = "passthru(" nocase wide ascii
        $cmd11 = "eval(" nocase wide ascii
        $os_cmd1 = "cat " nocase wide ascii
        $os_cmd2 = "ls " nocase wide ascii
        $os_cmd3 = "dir " nocase wide ascii
        $os_cmd4 = "whoami" nocase wide ascii
        $os_cmd5 = "ping " nocase wide ascii
        $os_cmd6 = "net " nocase wide ascii
        $os_cmd7 = "netstat" nocase wide ascii
    condition:
        2 of ($cmd*) and 1 of ($os_cmd*)
}

rule PathTraversal {
    meta:
        description = "Détecte les tentatives de traversée de répertoire"
        severity = "High"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $pt1 = "../" nocase wide ascii
        $pt2 = "..\\" nocase wide ascii
        $pt3 = "/.." nocase wide ascii
        $pt4 = "\\.." nocase wide ascii
        $pt5 = "%2e%2e%2f" nocase wide ascii
        $pt6 = "%2e%2e/" nocase wide ascii
        $pt7 = "..%2f" nocase wide ascii
        $pt8 = "%252e%252e%252f" nocase wide ascii
        $pt9 = "etc/passwd" nocase wide ascii
        $pt10 = "win.ini" nocase wide ascii
        $pt11 = "boot.ini" nocase wide ascii
        $pt12 = "etc/shadow" nocase wide ascii
    condition:
        2 of them
}

rule JWT_Manipulation {
    meta:
        description = "Détecte les manipulations potentielles de JWT"
        severity = "High"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $jwt_header = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/ nocase wide ascii
        $jwt_none = /"alg"\s*:\s*"none"/ nocase wide ascii
        $jwt_weak = /"alg"\s*:\s*"HS256"/ nocase wide ascii
    condition:
        $jwt_header and ($jwt_none or $jwt_weak)
}

rule NodeJS_Deserialization {
    meta:
        description = "Détecte les charges utiles de désérialisation Node.js"
        severity = "Critical"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $node_serialize = "_$$ND_FUNC$$_" nocase wide ascii
        $node_rce = /\{"rce"\s*:\s*"_\$\$ND_FUNC\$\$_function/ nocase wide ascii
        $eval_call = "eval('" nocase wide ascii
        $require = "require('" nocase wide ascii
        $child_process = "child_process" nocase wide ascii
        $exec = ".exec(" nocase wide ascii
    condition:
        $node_serialize or $node_rce or ($eval_call and ($require or $child_process or $exec))
}

rule File_Upload_Bypass {
    meta:
        description = "Détecte les tentatives de contournement de validation de téléchargement de fichiers"
        severity = "Medium"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $double_extension1 = ".php.jpg" nocase wide ascii
        $double_extension2 = ".php.png" nocase wide ascii
        $double_extension3 = ".php.gif" nocase wide ascii
        $double_extension4 = ".asp.jpg" nocase wide ascii
        $double_extension5 = ".jsp.png" nocase wide ascii
        $null_byte1 = ".php%00" nocase wide ascii
        $null_byte2 = ".php\x00" nocase wide ascii
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" nocase wide ascii
        $magic_pdf = "%PDF" nocase wide ascii 
        $magic_gif = "GIF8" nocase wide ascii 
        $magic_png = ".PNG" nocase wide ascii 
        $php_tag = "<?php" nocase wide ascii
    condition:
        any of ($double_extension*) or 
        any of ($null_byte*) or 
        ($php_tag and (($magic_pdf at 0) or ($magic_gif at 0) or ($magic_png at 0))) or 
        $eicar
}

rule Prototype_Pollution {
    meta:
        description = "Détecte les tentatives de pollution de prototype JavaScript"
        severity = "High"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $proto1 = "__proto__" nocase wide ascii
        $proto2 = "constructor" nocase wide ascii
        $proto3 = "prototype" nocase wide ascii
        $function1 = "Object.assign" nocase wide ascii
        $function2 = "Object.defineProperty" nocase wide ascii
        $function3 = "lodash.merge" nocase wide ascii
        $function4 = "jQuery.extend" nocase wide ascii
    condition:
        (any of ($proto*)) and (any of ($function*))
}

rule NoSQL_Injection {
    meta:
        description = "Détecte les schémas d'injection NoSQL"
        severity = "High"
        author = "Security Analyst" 
        date = "2025-05-15"
    strings:
        $nosql1 = "$where:" nocase wide ascii
        $nosql2 = "$gt:" nocase wide ascii
        $nosql3 = "$ne:" nocase wide ascii
        $nosql4 = "$regex:" nocase wide ascii
        $nosql5 = "$in:" nocase wide ascii
        $nosql6 = "$or:" nocase wide ascii
        $nosql7 = "$and:" nocase wide ascii
        $payload1 = "true, $where:" nocase wide ascii
        $payload2 = "1, $where:" nocase wide ascii
        $payload3 = /{"username":\s*{\s*"\$ne":\s*"/ nocase wide ascii
        $payload4 = /{"password":\s*{\s*"\$ne":\s*"/ nocase wide ascii
    condition:
        3 of ($nosql*) or any of ($payload*)
}

rule Juice_Shop_Credentials {
    meta:
        description = "Détecte des informations d'identification potentielles de Juice Shop"
        severity = "Medium"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $admin_email = "admin@juice-sh.op" nocase wide ascii
        $default_pass = "admin123" nocase wide ascii
        $api_key = /apiKey=[A-Za-z0-9]{10,50}/ nocase wide ascii
        $jwt = /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\./ nocase wide ascii
        $hash_pattern = /[a-f0-9]{32}/ nocase wide ascii 
        $hash_pattern2 = /[a-f0-9]{40}/ nocase wide ascii 
        $hash_pattern3 = /[a-f0-9]{64}/ nocase wide ascii
    condition:
        any of them
}

rule CSRF_Vulnerability {
    meta:
        description = "Détecte les potentielles vulnérabilités CSRF"
        severity = "High"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $form1 = "<form" nocase wide ascii
        $form2 = "method=\"post\"" nocase wide ascii
        $form3 = "method='post'" nocase wide ascii
        $ajax1 = "$.ajax" nocase wide ascii
        $ajax2 = "$.post" nocase wide ascii
        $ajax3 = "fetch(" nocase wide ascii
        $ajax4 = "xhr.open(" nocase wide ascii
        $csrf_token1 = "csrf" nocase wide ascii
        $csrf_token2 = "xsrf" nocase wide ascii
        $csrf_token3 = "_token" nocase wide ascii
    condition:
        ((any of ($form*)) or (any of ($ajax*))) and 
        not any of ($csrf_token*)
}

rule Insecure_File_Handling {
    meta:
        description = "Détecte les manipulations potentiellement dangereuses de fichiers"
        severity = "High"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $file_op1 = "fs.readFile" nocase wide ascii
        $file_op2 = "fs.writeFile" nocase wide ascii
        $file_op3 = "fs.unlink" nocase wide ascii
        $file_op4 = "fs.readFileSync" nocase wide ascii
        $file_op5 = "fs.writeFileSync" nocase wide ascii
        $file_op6 = "createReadStream" nocase wide ascii
        $file_op7 = "createWriteStream" nocase wide ascii
        $path_var1 = "req.params" nocase wide ascii
        $path_var2 = "req.query" nocase wide ascii
        $path_var3 = "req.body" nocase wide ascii
        $sanit1 = "path.normalize" nocase wide ascii
        $sanit2 = "path.resolve" nocase wide ascii
        $sanit3 = "sanitize" nocase wide ascii
        $sanit4 = "validate" nocase wide ascii
    condition:
        (any of ($file_op*)) and
        (any of ($path_var*)) and
        not any of ($sanit*)
}

rule Weak_Crypto {
    meta:
        description = "Détecte l'utilisation d'algorithmes cryptographiques faibles"
        severity = "Medium"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $md5 = "md5" nocase wide ascii
        $sha1 = "sha1" nocase wide ascii
        $des = "createDes" nocase wide ascii
        $rc4 = "rc4" nocase wide ascii
        $blowfish = "blowfish" nocase wide ascii
        $ecb = "createCipheriv('aes-128-ecb'" nocase wide ascii
        $ecb2 = "createCipheriv('aes-256-ecb'" nocase wide ascii
        $ecb3 = "createCipheriv('des-ecb'" nocase wide ascii
        $weak_key = "key.length < 16" nocase wide ascii
    condition:
        any of them
}

rule Sensitive_DataExposure {
    meta:
        description = "Détecte l'exposition de données sensibles"
        severity = "High"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $cc = /\b4[0-9]{12}(?:[0-9]{3})?\b/ nocase wide ascii
        $ssn = /\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b/ nocase wide ascii
        $email = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b/ nocase wide ascii
        $pwd1 = "password" nocase wide ascii
        $pwd2 = "passwd" nocase wide ascii
        $pwd3 = "secret" nocase wide ascii
        $key1 = "api_key" nocase wide ascii
        $key2 = "apikey" nocase wide ascii
        $key3 = "secret_key" nocase wide ascii
        $key4 = "private_key" nocase wide ascii
        $http_log = /console\.log\(.*req/ nocase wide ascii
    condition:
        any of them
}

rule Remote_CodeExecution {
    meta:
        description = "Détecte les possibles vecteurs d'exécution de code à distance"
        severity = "Critical"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $dangerous1 = "eval(" nocase wide ascii
        $dangerous2 = "new Function(" nocase wide ascii
        $dangerous3 = "setTimeout(" nocase wide ascii
        $dangerous4 = "setInterval(" nocase wide ascii
        $dangerous5 = "child_process" nocase wide ascii
        $dangerous6 = "execSync" nocase wide ascii
        $dangerous7 = "spawnSync" nocase wide ascii
        $dangerous8 = "spawn(" nocase wide ascii
        $dangerous9 = "exec(" nocase wide ascii
        $dynamic1 = "require(req" nocase wide ascii
        $dynamic2 = "require(res" nocase wide ascii
        $dynamic3 = "require(bod" nocase wide ascii
        $dynamic4 = "require(par" nocase wide ascii
    condition:
        any of ($dangerous*) and any of ($dynamic*)
}

rule Server_Misconfiguration {
    meta:
        description = "Détecte des indicateurs potentiels de mauvaise configuration de serveur"
        severity = "Medium"
        author = "Security Analyst"
        date = "2025-05-15"
    strings:
        $header1 = "X-Powered-By" nocase wide ascii
        $header2 = "Server:" nocase wide ascii
        $debug1 = "DEBUG" nocase wide ascii
        $debug2 = "DEVELOPMENT" nocase wide ascii
        $debug3 = "DEV_MODE" nocase wide ascii
        $access_control1 = "Access-Control-Allow-Origin: *" nocase wide ascii
        $access_control2 = "Access-Control-Allow-Credentials: true" nocase wide ascii
        $directory_listing = "Directory listing" nocase wide ascii
        $error1 = "stack:" nocase wide ascii
        $error2 = "Error:" nocase wide ascii
        $error3 = "at Object.<anonymous>" nocase wide ascii
        $error4 = "at Module._compile" nocase wide ascii
        $error5 = "at emitTwo" nocase wide ascii
    condition:
        2 of them
}