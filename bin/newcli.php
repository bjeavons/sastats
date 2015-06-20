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

$application = new Application();
$application->addCommands(array(
    new DownloadCommand($config),
    new ExtractCommand($config),
));
$application->run();
