<?php

namespace DrupalorgParser;

use QueryPath\QueryPath;

/**
 * Class SaParser for parsing Drupal.org Security Advisories
 */
class SaParser {

    /**
     * @var string
     */
    const BASE_URL = 'https://drupal.org';

    /**
     * @var QueryPath
     */
    protected $doc;

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
