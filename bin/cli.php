<?php

/**
 * @file
 *
 * CLI for sastats
 *
 * @todo future commands
 *  - download specific SA by ID
 *  - download specific SAs by list page
 *  - test SA parsing
 */

require_once __DIR__.'/../vendor/autoload.php';

use DrupalorgParser\SaParser;

// Config and options.
$type = !empty($argv[1]) ? $argv[1] : null;
$command = !empty($argv[2]) ? $argv[2] : 'download';
$data_dir = './data/';
$html_output_dir = $data_dir . $type . '/html/';
$last_run_file = $data_dir . 'LASTDOWNLOAD.json';
$data_out_file = $data_dir . $type . '/DATA.tsv';
$last_run = array();
$until = !empty($argv[3]) ? $argv[3] : null;

// Validate arguments and setup.
if (empty($type) || ($type !== 'core' && $type !== 'contrib')) {
    print "Pass 'core' or 'contrib' to operate on specific SA types." . PHP_EOL;
    print "php bin/cli.php core download" . PHP_EOL;
    exit(1);
}
if (empty($command) || ($command !== 'download' && $command !== 'extract')) {
    print "Supported commands are 'download' or 'extract'. Defaults to 'download' to save specific SAs to the data directory." . PHP_EOL;
    print "php bin/cli.php core download" . PHP_EOL;
    exit(1);
}
if (!file_exists($data_dir)) {
    print "Local data export directory does not exist. Run install.sh." . PHP_EOL;
    exit(1);
}

if (file_exists($last_run_file)) {
    $content = file_get_contents($last_run_file);
    $last_run = json_decode($content, true);
    if (is_null($until) && !empty($last_run[$type . '_latest_id'])) {
        $until = $last_run[$type . '_latest_id'];
    }
}
$parser = new SaParser();

// Download SAs from drupal.org.
if ($command === 'download') {
    $written = 0;
    $urls = $parser->getAdvisoryIds($type, $until);
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
            $file = $id . '.html';
            $max = ($id > $max) ? $id : $max;
            if (file_exists($html_output_dir . $file)) {
                continue;
            }
            $content = file_get_contents($parser::BASE_URL . '/' . $path);
            file_put_contents($html_output_dir . $file, $content);
            $written++;
        }

        // Update state file.
        $last_run['type'] = $type;
        $last_run[$type . '_latest_id'] = $max;
        $last_run['time'] = time();
        file_put_contents($last_run_file, json_encode($last_run));
        print "Exported $written SAs since $until" . PHP_EOL;
    }
}
// Extract SA data from saved SAs.
elseif ($command === 'extract') {
    $store = array();
    foreach (scandir($html_output_dir) as $file) {
        if (strpos($file, 'SA-') !== false) {
            $content = file_get_contents($html_output_dir . $file);
            $data = $parser->parseAdvisory($content);
            $store[] = $data;
        }
    }
    // Write out data.
    if (!empty($store)) {
        $handle = fopen($data_out_file, 'w+');
        fputcsv($handle, array_keys($store[0]), chr(9));
        foreach ($store as $row) {
            fputcsv($handle, $row, chr(9));
        }
        fclose($handle);
    }
}
