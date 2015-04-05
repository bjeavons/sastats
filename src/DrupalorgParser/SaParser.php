<?php

namespace DrupalorgParser;

use Goutte\Client;
use Symfony\Component\DomCrawler\Crawler;

/**
 * Class SaParser for parsing Drupal.org Security Advisories
 */
class SaParser {

    /**
     * @var string
     */
    const BASE_URL = 'https://www.drupal.org';

    /**
     * @var \Symfony\Component\DomCrawler\Crawler
     */
    protected $crawler;

    /**
     * @var \Goutte\Client
     */
    protected $client;

    /**
     * @var array
     */
    protected $dataStore;

    /**
     * @param array $data_store
     *
     */
    public function __construct($data_store = array())
    {
        $this->dataStore = $data_store;
        $this->client = new Client();
    }

    /**
     * Get SA IDs and paths from listing pages.
     *
     * @param string $type
     *   SA type to retrieve, 'core' or 'contrib'.
     * @param string $until
     *   SA ID to retrieve up to.
     *
     * @return array
     *   Array of SA IDs indexed by path.
     */
    public function getAdvisoryIds($type, $until = null)
    {
        $urls = array();
        $list_url = self::BASE_URL . '/security';
        if ($type === 'contrib') {
            $list_url .= '/contrib';
        }

        $crawler = $this->client->request('GET', $list_url);
        $filter = $crawler->filter('div.views-row');
        foreach ($filter as $element) {
            $crawler = new Crawler($element);
            $path = ltrim($crawler->filter('a')->attr('href'), '/');
            $id = $crawler->filter('li')->text();
            $id = trim(str_replace('Advisory ID:', '', $id));
            // Halt if reached ID limit.
            if ($until && $id === $until) {
                break;
            }
            $urls[$path] = $id;
        }
        // @todo add paging support till $until
        return $urls;
    }

    /**
     * Parse SA list page and store SA data.
     *
     * @param string $html
     *   HTML page of list of SAs e.g. content of http://drupal.org/security/contrib
     */
    public function parseList($html)
    {
        // @todo handle URL ?
        foreach (htmlqp($html, 'div.views-row') as $row) {

            $element = $row->find('.node');
            $id = $this->extractTitle($element->text());
            $this->setData($id, 'advisory', $id);
            $link = self::BASE_URL . $element->find('a')->attr('href');
            $this->setData($id, 'link', $link);
            foreach ($row->find('li') as $listElement) {
                $text = $listElement->text();
                switch ($text) {
                    case strpos($text, 'Project') === 0:
                        $this->setData($id, 'project', $this->extractProject($text));
                        break;
                    case strpos($text, 'Date') === 0:
                        $this->setData($id, 'date', $this->extractDate($text));
                        break;
                    case strpos($text, 'Vulnerability') === 0:
                        $this->setData($id, 'vulnerabilities', $this->extractVulnerability($text));
                        break;
                }
            }
        }
    }

    /**
     * Parse SA page and store SA data.
     *
     * @param string $html
     *   HTML page for a SA.
     */
    public function parseSa($html)
    {

    }

    /**
     * Get stored SA data.
     *
     * @return array
     *      Array of stored SA data keyed by advisory ID.
     *
     *      @code
     *      array(
     *          'SA-CONTRIB-2013-001' => array(
     *              'advisory' => 'SA-CONTRIB-2013-001',
     *              'link' => 'http://drupal.org/node/91990',
     *              'project' => 'Example module',
     *              'date' => '2013-September-18',
     *              'vulnerabilities' => 'Cross Site Scipting, Acces bypass',
     *          ),
     *          ...
     *      )
     */
    public function getData()
    {
        return $this->dataStore;
    }

    /**
     * @param $id
     * @param $type
     * @param $value
     */
    protected function setData($id , $type, $value)
    {
        $this->dataStore[$id][$type] = $value;
    }

    protected function extractTitle($text)
    {
        list($text,) = explode(' - ', $text);
        return trim($text);
    }

    /**
     * @param $text
     * @return string
     */
    protected function extractAdvisoryId($text)
    {
        list(,$text) = explode(':', $text);
        return trim($text);
    }

    /**
     * @param $text
     * @return string
     */
    protected function extractProject($text)
    {
        list(,$text) = explode(':', $text);
        list($project,) = explode('(third', $text);
        return trim($project);
    }

    /**
     * @param $text
     * @return string
     */
    protected function extractDate($text)
    {
        list(,$text) = explode(':', $text);
        return trim($text);
    }

    /**
     * @param $text
     * @return string
     */
    protected function extractVulnerability($text)
    {
        list(,$text) = explode(':', $text);
        return trim($text);
    }

}
