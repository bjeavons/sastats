<?php

namespace DrupalorgParser;

use QueryPath\QueryPath;

/**
 *
 */
class Parser {

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
     *
     */
    public function __construct($data_store = array())
    {
        $this->dataStore = $data_store;
    }

    /**
     *
     * @param string $html
     */
    public function parseList($html)
    {
        foreach (htmlqp($html, 'div.views-row') as $row) {

            $element = $row->find('.node-title');
            $id = $this->extractTitle($element->text());
            $link = self::BASE_URL . $element->find('a')->attr('href');
            foreach ($row->find('li') as $listElement) {
                $text = $listElement->text();
                switch ($text) {
                    case strpos($text, 'Project') !== FALSE:
                        $project = $this->extractProject($text);

                        break;
                    case strpos($text, 'Date') !== FALSE:
                        $date = $this->extractDate($text);

                        break;
                    case strpos($text, 'Vulnerability') !== FALSE:
                        $vulnerability = $this->extractVulnerability($text);

                        break;
                }
            }
            // @todo wat if data not found

            $this->setData($id, 'advisory', $id);
            $this->setData($id, 'link', $link);
            $this->setData($id, 'project', $project);
            $this->setData($id, 'date', $date);
            $this->setData($id, 'vulnerability', $vulnerability);
        }

    }

    /**
     * @return array
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
    protected function setData($id , $type, $value) {
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
