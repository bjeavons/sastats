<?php

require_once __DIR__.'/../vendor/autoload.php';

use DrupalorgParser\SaParser;

$type = !empty($argv[1]) ? $argv[1] : null;
$i = !empty($argv[2]) ? $argv[2] : 0;

if (empty($type) || ($type !== 'core' && $type !== 'contrib')) {
    print "Pass 'core' or 'contrib' to generate stats from export/* core or contrib files. Optionally pass count of files to limit data for.\n";
    exit(1);
}

$p = new SaParser();

$continue = true;
do {
    $html = @file_get_contents(__DIR__."/../export/$type-$i.html");
    if (empty($html)) {
        $continue = false;
    }
    else {
        $p->parseList($html);
        $i++;
    }
}
while ($continue);

$data = $p->getData();

if (!empty($data)) {
    foreach ($data as $row) {
        print $row['advisory'].",".$row['project'].",".$row['link'].",".$row['date'].",".$row['vulnerabilities']."\n";
    }
}

