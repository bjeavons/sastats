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

    public function __construct()
    {
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
     * Parse SA page and return structured data.
     *
     * @param string $html
     *   HTML page for a SA.
     *
     * @return array
     *   Array with elements:
     *     id
     *     project_name_short
     *     project_name
     *     versions
     *     date
     *     security_risk
     *     vulnerabilities
     */
    public function parseAdvisory($html)
    {
        $data = array();
        $crawler = new Crawler($html);
        // Filter down to content for the node.
        $crawler = $crawler->filter('div.node > div.content')->eq(0);

        // First ul contains the prime advisory data elements.
        $elements = $crawler->filter('ul')->eq(0)->filter('li');
        foreach ($elements as $element) {
            $element_crawler = new Crawler($element);
            $this->parseAdvisoryElement($element_crawler, $data);
        }

        // Other interesting data can be parsed out based on section header.
        $sections = $elements = $crawler->filter('ul')->eq(0)->nextAll();
        $this->parseAdvisorySections($sections, $data);

        /*foreach ($lists as $list) {
            $list_crawler = new Crawler($list);
            $elements = $list_crawler->filter('li');
            foreach ($elements as $element) {
                $element_crawler = new Crawler($element);
                $this->parseAdvisoryElement($element_crawler, $data);
            }
        }*/
        return $data;
    }

    /**
     * Parse elements of an Advisory into structured data.
     *
     * @param Crawler $crawler
     * @param array $data
     */
    protected function parseAdvisoryElement(Crawler $crawler, array &$data)
    {
        $text = $crawler->text();
        switch (true) {
            case strpos($text, 'Advisory ID:') === 0:
                $data['id'] = trim(str_replace('Advisory ID: ', '', $text));
                break;

            case strpos($text, 'Version:') === 0:
                $versions = trim(str_replace('Version: ', '', $text));
                $data['versions'] = array_map('trim', explode(',', $versions));
                break;

            case strpos($text, 'Project:') === 0:
                $data['project_name'] = trim($crawler->filter('a')->text());
                $url = ltrim($crawler->filter('a')->attr('href'), '/');
                $data['project_name_short'] = basename($url);
                break;

            case strpos($text, 'Date:') === 0:
                $data['date'] = trim(str_replace('Date: ', '', $text));
                break;

            case strpos($text, 'Security risk:') === 0:
                $data['security_risk'] = trim(str_replace('Security risk: ', '', $text));
                break;

            case strpos($text, 'Vulnerability:') === 0:
                $vulnerabilities = trim(str_replace('Vulnerability: ', '', $text));
                $data['vulnerabilities'] = array_map('trim', explode(',', $vulnerabilities));
                break;
        }
    }

    /**
     * Parse sections of a Advisory and extract certain data.
     *
     * @param $sections
     * @param array $data
     */
    protected function parseAdvisorySections($sections, array &$data)
    {
        foreach ($sections as $section) {
            $crawler = new Crawler($section);
            // Extract based on header section.
            if ($crawler->nodeName() == 'h2') {
                $text = trim($crawler->text());
                switch (true) {
                    case strpos($text, 'CVE identifier(s) issued') === 0:
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $data['cves'][] = $element_crawler->text();
                        }
                        break;

                    case strpos($text, 'Versions affected') === 0:
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $data['versions_affected'][] = $element_crawler->text();
                        }
                        break;

                    case strpos($text, 'Solution') === 0:
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $data['solution'][] = $element_crawler->text();
                            // @todo extract release nodes
                        }
                        break;

                    case strpos($text, 'Reported by') === 0:
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $data['reported_by'][] = $element_crawler->text();
                            // @todo extract username and uid
                        }
                        break;

                    case strpos($text, 'Fixed by') === 0:
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $data['fixed_by'][] = $element_crawler->text();
                            // @todo extract username and uid
                        }
                        break;

                    case strpos($text, 'Coordinated by') === 0:
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $data['coordinated_by'][] = $element_crawler->text();
                            // @todo extract username and uid
                        }
                        break;
                }
            }

        }
    }

}
