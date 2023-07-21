<?php

namespace PPOLib;

function autoload($className) {
    $className = ltrim($className, '\\');


    if (strpos($className, 'PPOLib\\') === 0) {
        $path = __DIR__ . DIRECTORY_SEPARATOR. strtolower(str_replace('\\', DIRECTORY_SEPARATOR, str_replace('PPOLib\\', '', $className))) . '.php';
    } else {
        return;
    }
    require_once $path;
}
spl_autoload_register('\PPOLib\autoload');
