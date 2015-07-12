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
                $this->manipulateData($data);

                $file = $json_output_dir . $data['id'] . '.json';
                $this->writeJsonFile($data, $file);
                $files++;
            }
        }
        $output->writeln("Parsed $files SAs and extracted data to JSON");
    }

    /**
     * Manipulate extracted data to provide simplified fields.
     *
     * Adds fieldsto JSON data:
     *   vulnerability_ids
     *
     * @param array $data
     */
    protected function manipulateData(&$data)
    {
        $vulnerability_ids = array();
        if (!empty($data['vulnerabilities'])) {

            $vulnerabilities = strtolower($data['vulnerabilities']);
            if (strpos($vulnerabilities, 'site scripting') || strpos($vulnerabilities, 'xss')) {
                $vulnerability_ids[] = 'XSS';
            }
            if (strpos($vulnerabilities, 'site request forger')) {
                $vulnerability_ids[] = 'CSRF';
            }
            if (strpos($vulnerabilities, 'sql inject')) {
                $vulnerability_ids[] = 'SQLi';
            }
            if (strpos($vulnerabilities, 'of service')) {
                $vulnerability_ids[] = 'DOS';
            }
            if (strpos($vulnerabilities, 'access') || strpos($vulnerabilities, 'authoriz')) {
                $vulnerability_ids[] = 'Access bypass';
            }
            if (strpos($vulnerabilities, 'execution')) {
                $vulnerability_ids[] = 'Code execution';
            }
            if (strpos($vulnerabilities, 'information disclosure')) {
                $vulnerability_ids[] = 'Information disclosure';
            }
            $vulnerability_ids = implode(',', array_unique($vulnerability_ids));
        }
        $data['vulnerability_ids'] = $vulnerability_ids;
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
