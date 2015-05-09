<?php

/**
 * @file
 *
 * Class for Drupal.org SA parsing.
 */

namespace DrupalorgParser;

use Goutte\Client;
use Symfony\Component\DomCrawler\Crawler;

/**
 * Class SaParser for parsing Drupal.org Security Advisories
 */
class SaParser
{

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
        $data = array();
        $page_param = '';
        $page = 0;

        $list_url = self::BASE_URL . '/security';
        if ($type === 'contrib') {
            $list_url .= '/contrib';
        }

        $crawler = $this->client->request('GET', $list_url . $page_param);
        // Get max pager pages.
        $filter = $crawler->filter('div.content')->filter('li.pager-last > a');
        $href = trim($filter->attr('href'));
        $last_page = (int) substr($href, strpos($href, '?page=') + 6);

        while ($page <= $last_page) {
            $page++;
            $page_ids = $this->parseIds($crawler);
            $data = array_merge($data, $page_ids);
            // Halt if last SA was found or reached last page.
            if (in_array($until, $data) || $page > $last_page) {
                break;
            }
            $page_param = '?page=' . $page;
            $crawler = $this->client->request('GET', $list_url . $page_param);
        }

        return $data;
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
        $data = array(
            'id' => '',
            'project_name' => '',
            'project_name_short' => '',
            'versions' => '',
            'date' => '',
            'security_risk' => '',
            'vulnerabilities' => '',
            'cves' => '',
            'versions_affected' => '',
            'solution' => '',
            'reported_by' => '',
            'fixed_by' => '',
            'coordinated_by' => '',
        );
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

        return $data;
    }

    /**
     * Parse SA list into SA IDs.
     *
     * @param Crawler $crawler
     *   Crawler on SA list page.
     *
     * @return array
     *   Array of SA IDs indexed by remote path.
     */
    protected function parseIds($crawler)
    {
        $ids = array();
        $filter = $crawler->filter('div.views-row');
        foreach ($filter as $element) {
            $crawler = new Crawler($element);
            $path = ltrim($crawler->filter('a')->attr('href'), '/');
            $id = $crawler->filter('li')->text();
            if (strpos($id, 'Advisory ID') !== false) {
                $id = trim(str_replace('Advisory ID:', '', $id));
                $ids[$path] = $id;
            }
            else {
                // One SA has no advisory ID so just use node path.
                $ids[$path] = $path;
            }
        }
        return $ids;
    }

    /**
     * Parse elements of an Advisory into structured data.
     *
     * @param Crawler $crawler
     * @param array $data
     */
    protected function parseAdvisoryElement(Crawler $crawler, array &$data)
    {
        $text = trim($crawler->text());
        switch (true) {
            case strpos($text, 'Advisory ID:') === 0:
                $id = str_replace('Advisory ID: ', '', $text);
                $data['id'] = trim($id, '. ');
                break;

            case strpos($text, 'Version:') === 0:
            case strpos($text, 'Versions:') === 0:
                $versions = preg_replace('/[Vv]ersions?: /', '', $text);
                $versions = preg_replace('/ and /', ', ', $versions);
                $data['versions'] = trim($versions);
                break;

            case strpos($text, 'Project:') === 0:
            case strpos($text, 'Projects:') === 0:
                try {
                    $project_name = trim($crawler->filter('a')->text());
                    $url = ltrim($crawler->filter('a')->attr('href'), '/');
                    $data['project_name_short'] = basename($url);
                }
                catch (\InvalidArgumentException $e) {
                    // Not all SAs link to project. E.g. SA-2008-031
                    $project_name = preg_replace('/Projects?: /', '', $text);
                    $data['project_name_short'] = '';
                }
                if (empty($project_name)) {
                    // Some project links are incorrect. E.g. DRUPAL-SA-CONTRIB-2012-029.
                    $project_name = preg_replace('/Projects?: /', '', $text);
                }
                $project_name = preg_replace('/\(third.?party (module|theme)s?\)/i', '', trim($project_name));
                $project_name = preg_replace('/\multiple third.?party (module|theme)s?/i', '', $project_name);
                $data['project_name'] = trim($project_name, '. -');;
                break;

            case strpos($text, 'Date:') === 0:
                $data['date'] = trim(str_replace('Date: ', '', $text), '. ');
                break;

            case strpos($text, 'Security risk:') === 0:
            case strpos($text, 'Security risks:') === 0:
                $security_risk = preg_replace('/Security risks?: /i', '', $text);
                $security_risk = preg_replace('/\(definition of risk levels\)/i', '', $security_risk);
                $data['security_risk'] = trim($security_risk, '. ');
                break;

            case strpos($text, 'Vulnerability:') === 0:
            case strpos($text, 'Vulnerabilities:') === 0:
                $vulnerabilities  = preg_replace('/Vulnerabilit(y|ies): /i', '', $text);
                $data['vulnerabilities'] = trim($vulnerabilities, '. ');
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
                        $placeholder = "A CVE identifier will be requested";
                        $cves = array();
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $text = $element_crawler->text();
                            if (strpos($text, $placeholder) === FALSE) {
                                $cves[] = $text;
                            }
                        }
                        $data['cves'] = implode(', ', $cves);
                        break;

                    case strpos($text, 'Versions affected') === 0:
                        $versions_affected = array();
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $versions_affected[] = $element_crawler->text();
                        }
                        $data['versions_affected'] = implode(', ' , $versions_affected);
                        break;

                    case strpos($text, 'Solution') === 0:
                        $solution = array();
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $solution[] = trim($element_crawler->text());
                            // @todo extract release nodes
                        }
                        $data['solution'] = implode(', ', $solution);
                        break;

                    case strpos($text, 'Reported by') === 0:
                        $reported_by = array();
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $reported_by [] = trim($element_crawler->text());
                            // @todo extract username and uid
                        }
                        $data['reported_by'] = implode(', ', $reported_by);
                        break;

                    case strpos($text, 'Fixed by') === 0:
                        $fixed_by = array();
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $fixed_by[] = trim($element_crawler->text());
                            // @todo extract username and uid
                        }
                        $data['fixed_by'] = implode(', ', $fixed_by);
                        break;

                    case strpos($text, 'Coordinated by') === 0:
                        $coordinated_by = array();
                        // Get the exact next list.
                        $list_elements = $crawler->nextAll()->filter('ul')->eq(0)->filter('li');
                        foreach ($list_elements as $element) {
                            $element_crawler = new Crawler($element);
                            $coordinated_by[] = trim($element_crawler->text());
                            // @todo extract username and uid
                        }
                        $data['coordinated_by'] = implode(', ', $coordinated_by);
                        break;
                }
            }

        }
    }

}
