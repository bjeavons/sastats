<?php

/**
 * @file
 * Combine data from JSON SA
 */

namespace SaStats\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

use DrupalorgParser\SaParser;

/**
 * Class CombineCommand
 * @package SaStats\Console
 */
class CombineCommand extends Command
{

    /**
     * @var array
     */
    protected $config;

    /**
     * @var string
     */
    protected $last_run_file;

    public function __construct(array $config = array())
    {
        parent::__construct();
        $this->config = $config;
        $this->last_run_file = $this->config['data_dir'] . $this->config['last_run_file'];
    }

    protected function configure()
    {
        $this
            ->setName('combine')
            ->setDescription('Load extracted data into combined tab-separated file')
            ->addArgument(
                'type',
                InputArgument::REQUIRED,
                'Extract from either core or contrib'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $store = array();
        $type = $input->getArgument('type');
        $json_input_dir = $this->config['data_dir'] . $type . '/json/';
        $data_out_file = $this->config['data_dir'] . $type . '/DATA.tsv';

        $parser = new SaParser();
        foreach (scandir($json_input_dir) as $file) {
            if (strpos($file, 'SA-') !== false) {
                $content = $this->readFile($json_input_dir . $file);
                $data = json_decode($content, true);
                // @todo limit fields?
                $store[] = $data;
            }
        }
        $parsed_count = count($store);
        // Write out data.
        if (!empty($store)) {
            $this->writeTsvFile($store, $data_out_file);
            $output->writeln("Read $parsed_count SAs and saved data to $data_out_file");
        }
    }

    /**
     * Read a file.
     *
     * @param string $file
     * @return string
     */
    protected function readFile($file)
    {
        return file_get_contents($file);
    }

    /**
     * Write array of data to TSV file.
     *
     * @param array $content
     * @param string $file
     */
    protected function writeTsvFile($content, $file)
    {
        $handle = fopen($file, 'w+');
        fputcsv($handle, array_keys($content[0]), chr(9));
        foreach ($content as $row) {
            fputcsv($handle, $row, chr(9));
        }
        fclose($handle);
    }
}
