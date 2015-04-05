<?php

require_once __DIR__.'/../vendor/autoload.php';

use DrupalorgParser\SaParser;

// Config and options.
$type = !empty($argv[1]) ? $argv[1] : null;
$i = !empty($argv[2]) ? $argv[2] : 0;
$data_dir = './data/';
$html_output_dir = $data_dir . $type . '/html/';
$last_run_file = $data_dir . 'LASTRUN.json';
$last_run = array();
$until = null;

if (empty($type) || ($type !== 'core' && $type !== 'contrib')) {
    print "Pass 'core' or 'contrib' to save specific SAs to the data directory." . PHP_EOL;
    exit(1);
}

$parser = new SaParser();

if (file_exists($last_run_file)) {
    $content = file_get_contents($last_run_file);
    $last_run = json_decode($content, true);
    if (!empty($last_run[$type . '_max_id'])) {
        $until = $last_run[$type . '_max_id'];
    }
}

if ($until) {
    $file = $html_output_dir . $until . '.html';
    $content = file_get_contents($file);
    $data = $parser->parseAdvisory($content);
    var_export($data);
}

/*$urls = $parser->getAdvisoryIds($type, $until);
if (empty($urls)) {
    if ($until) {
        print "No new $type SAs since $until" . PHP_EOL;
    }
    else {
        print "No SAs found, probably an error in parsing" . PHP_EOL;
    }
}
else{
    $max = '-1';
    foreach ($urls as $path => $id) {
        $content = file_get_contents($parser::BASE_URL . '/' . $path);
        $file = $id . '.html';
        file_put_contents($html_output_dir . $file, $content);
        $max = ($id > $max) ? $id : $max;
    }

    $last_run['type'] = $type;
    $last_run[$type . '_max_id'] = $max;
    $last_run['time'] = time();
    file_put_contents($last_run_file, json_encode($last_run));
}*/
