<?php

/**
 * @file
 * Download SAs from drupal.org
 */

namespace SaStats\Console;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

use DrupalorgParser\SaParser;

/**
 * Class DownloadCommand
 * @package SaStats\Console
 */
class DownloadCommand extends Command
{

    /**
     * @var array
     */
    protected $config;

    /**
     * @var string
     */
    protected $last_run_file;

    /**
     * @var OutputInterface
     */
    protected $out;

    /**
     * @var SaParser
     */
    protected $parser;

    public function __construct(array $config = array())
    {
        parent::__construct();
        $this->config = $config;
        $this->last_run_file = $this->config['data_dir'] . $this->config['last_run_file'];
        $this->parser = new SaParser();
    }

    protected function configure()
    {
        $this
            ->setName('download')
            ->setDescription('Download SAs from drupal.org')
            ->addArgument(
                'type',
                InputArgument::OPTIONAL,
                'Download either core or contrib, defaults to core'
            )
            ->addOption(
                'until',
                null,
                InputOption::VALUE_OPTIONAL,
                'SA ID to download up till'
            )
            ->addOption(
                'nid',
                null,
                InputOption::VALUE_OPTIONAL,
                'Specific SA node ID to download'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $this->out = $output;
        $until = null;
        $content = $this->readFile($this->last_run_file);
        $last_run = json_decode($content, true);

        $type = $input->getArgument('type');
        if ($type === 'core' || $type === 'contrib') {
            if ($input->getOption('until')) {
                $until = $input->getOption('until');
            }
            if (!$until && !empty($last_run[$type . '_latest_id'])) {
                $until = $last_run[$type . '_latest_id'];
            }
            $this->downloadFromList($type, $until);
        }
        elseif ($input->getOption('nid')) {
            $sa_nid = $input->getOption('nid');
            $this->downloadSaNid($sa_nid);
        }
    }

    /**
     * Download SAs from listing pages.
     *
     * @param string $type
     * @param string $until
     */
    protected function downloadFromList($type, $until = null)
    {
        $html_output_dir = $this->config['data_dir'] . $type . '/html/';
        $written = 0;
        $urls = $this->parser->getAdvisoryIds($type, $until);
        if (empty($urls)) {
            if ($until) {
                $this->out->writeln("No new $type SAs since $until");
                return;
            }
            else {
                $this->out->writeln("No SAs found, probably an error in parsing");
                return;
            }
        }
        $max = '-1';
        foreach ($urls as $path => $id) {
            $file = $id . '.html';
            $max = ($id > $max) ? $id : $max;
            if (file_exists($html_output_dir . $file)) {
                continue;
            }
            $content = $this->readFile(SaParser::BASE_URL . '/' . $path);
            $this->writeFile($content, $html_output_dir . $file);
            $written++;
        }

        // Update state file.
        $last_run['type'] = $type;
        $last_run[$type . '_latest_id'] = $max;
        $last_run['time'] = time();

        $this->writeFile(json_encode($last_run), $this->last_run_file);
        $this->out->writeln("Exported $written SAs since $until");
    }

    /**
     * Download a specific SA.
     *
     * @param string $nid
     */
    protected function downloadSaNid($nid)
    {
        $content = $this->readFile(SaParser::BASE_URL . '/node/' . $nid);
        $data = $this->parser->parseAdvisory($content);
        if (empty($data['id']) || emtpy($data['project_short_name'])) {
            $this->out->writeln("Unable to parse node $nid");
            return;
        }
        $type = $data['project_name_short'] === 'drupal' ? 'core' : 'contrib';

        $html_output_dir = $this->config['data_dir'] . $type . '/html/';
        $file = $html_output_dir . $data['id'] . '.html';
        $this->writeFile($content, $file);
        $this->out->writeln("Exported {$data['id']} to $file");
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
     * Write content to a file.
     *
     * @param string $content
     * @param string $file
     */
    protected function writeFile($content, $file)
    {
        file_put_contents($file, $content);
    }
}
