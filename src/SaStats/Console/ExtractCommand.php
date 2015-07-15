<?php

/**
 * @file
 * Extract data from downloaded SAs
 */

namespace SaStats\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

use DrupalorgParser\SaParser;

/**
 * Class ExtractCommand
 * @package SaStats\Console
 */
class ExtractCommand extends Command
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
            ->setName('extract')
            ->setDescription('Extract data from HTML SAs into JSON ')
            ->addArgument(
                'type',
                InputArgument::REQUIRED,
                'Extract from either core or contrib'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $type = $input->getArgument('type');
        $html_input_dir = $this->config['data_dir'] . $type . '/html/';
        $json_output_dir = $this->config['data_dir'] . $type . '/json/';
        $files = 0;

        $parser = new SaParser();
        foreach (scandir($html_input_dir) as $file) {
            if (strpos($file, 'SA-') !== false) {
                $content = $this->readFile($html_input_dir . $file);
                $data = $parser->parseAdvisory($content);

                $file = $json_output_dir . $data['id'] . '.json';
                $this->writeJsonFile($data, $file);
                $files++;
            }
        }
        $output->writeln("Parsed $files SAs and extracted data to JSON");
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
     * Write array of data to JSON file.
     *
     * @param array $content
     * @param string $file
     */
    protected function writeJsonFile($content, $file)
    {
        $content = json_encode($content);
        file_put_contents($file, $content);
    }
}
