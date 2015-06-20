<?php
//

require __DIR__ . '/../vendor/autoload.php';

use Symfony\Component\Console\Application;
use SaStats\Console\DownloadCommand;
use SaStats\Console\ExtractCommand;

$config = array(
    'data_dir' => getcwd() . '/data/',
    'last_run_file' => 'LASTDOWNLOAD.json',
);

if (!file_exists($config['data_dir'])) {
    print "Local data export directory does not exist. Run install.sh." . PHP_EOL;
    exit(1);
}

$application = new Application();
$application->addCommands(array(
    new DownloadCommand($config),
    new ExtractCommand($config),
));
$application->run();
