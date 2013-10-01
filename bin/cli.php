<?php

require_once __DIR__.'/../vendor/autoload.php';

use DrupalorgParser\Parser;

$p = new Parser();
$html = file_get_contents(__DIR__.'/../export/contrib-4.html');
$p->parseList($html);
$data = $p->getData();
foreach ($data as $row) {
    print $row['advisory'].",".$row['project'].",".$row['link'].",".$row['date'].",".$row['vulnerability']."\n";
}
