<?php

/**
 * @file
 *
 */

namespace SaStats\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

use DrupalorgParser\SaParser;

/**
 * Class DownloadCommand
 * @package SaStats\Console
 */
class DownloadCommand extends Command
{
    protected function configure()
    {
        $this
            ->setName('download')
            ->setDescription('Download SAs from drupal.org')
            ->addArgument(
                'type',
                InputArgument::REQUIRED,
                'Download either core or contrib'
            )
            ->addOption(
                'until',
                null,
                InputOption::VALUE_OPTIONAL,
                'SA ID to download up till'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $until = null;
        $type = $input->getArgument('type');
        if ($input->getOption('until')) {
            $until = $input->getOption('until');
        }

        // @todo inject in this config
        $data_dir = getcwd() . '/data/';
        $html_output_dir = $data_dir . $type . '/html/';
        $last_run_file = $data_dir . 'LASTDOWNLOAD.json';

        if (file_exists($last_run_file)) {
            $content = file_get_contents($last_run_file);
            $last_run = json_decode($content, true);
            if (is_null($until) && !empty($last_run[$type . '_latest_id'])) {
                $until = $last_run[$type . '_latest_id'];
            }
        }

        $written = 0;
        $parser = new SaParser();
        $urls = $parser->getAdvisoryIds($type, $until);
        if (empty($urls)) {
            if ($until) {
                $output->writeln("No new $type SAs since $until");
                return;
            }
            else {
                $output->writeln("No SAs found, probably an error in parsing");
                return;
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
            $output->writeln("Exported $written SAs since $until");
        }
    }
}
