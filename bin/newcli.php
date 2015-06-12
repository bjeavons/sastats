<?php
//

require __DIR__ . '/../vendor/autoload.php';

use SaStats\Console\DownloadCommand;
use Symfony\Component\Console\Application;

$application = new Application();
$application->add(new DownloadCommand());
$application->run();
