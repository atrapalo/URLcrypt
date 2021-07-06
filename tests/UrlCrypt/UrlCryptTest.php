<?php

namespace Test\Atrapalo\UrlCrypt;

use Atrapalo\UrlCrypt\UrlCrypt;
use PHPUnit\Framework\TestCase;

class UrlCryptTest extends TestCase
{
    /** @var UrlCrypt */
    private $urlCrypt;
    
    protected function setUp() : void
    {
        $this->urlCrypt = new UrlCrypt();
    }

    /**
     * @test
     */
    public function instance()
    {
        $this->assertInstanceOf(UrlCrypt::class, UrlCrypt::getInstance());
    }

    /**
     * @test
     * Test 300 strings of random characters for each length between 1 and 30.
     */
    public function arbitraryEncode()
    {
        for ($i = 1; $i < 31; $i++) {
            for ($n = 0; $n < 300; $n++) {
                $string = '';
                for ($z = 0; $z < $i; $z++) {
                    $string .= chr(rand(0, 255));
                }

                $this->assertEquals($string, $this->encodeAndDecode($string));
            }
        }
    }

    /**
     * @test
     */
    public function emptyString()
    {
        $this->assertEmpty($this->encodeAndDecode(''));
    }

    /**
     * @test
     */
    public function definedEncode()
    {
        $this->assertEquals('3f5h2ylqmfwg9', $this->urlCrypt->encode('Atrapalo'));
    }

    /**
     * @test
     */
    public function definedDecode()
    {
        $this->assertEquals('Atrapalo', $this->urlCrypt->decode('3f5h2ylqmfwg9'));
    }

    /**
     * @test
     * @expectedException \Exception
     */
    public function emptyKey()
    {
        $this->urlCrypt->encrypt('Atrapalo', '');
    }

    /**
     * @test
     */
    public function retroCompatibilityWithMcrypt()
    {
        $data = $this->urlCrypt->decrypt(
            'f5bA4z5vbd866x6zc91s90gfccvx6mlkkwjdrjlk1t6w7c8mgz34pm0jryhzqwntA0blxjv9zj5pwhArgvvwgng2pbtwgqt717tsh51',
            substr('42a845f31add7dc60abf8ad04fc2eb76', 0, 16)
        );

        $this->assertEquals('131,33398885611#EUR#24#HD#2_200_0_0_0_0_0#O#', $data);
    }

    /**
     * @test
     * @dataProvider encryptData
     * @param $string
     * @param $key
     */
    public function encryption($string, $key)
    {
        $encrypted = $this->urlCrypt->encrypt($string, $key);

        $this->assertEquals($string, $this->urlCrypt->decrypt($encrypted, $key));
    }

    /**
     * @test
     * @dataProvider encryptData
     * @param $string
     * @param $key
     */
    public function encryptionWithInstance($string, $key)
    {
        $urlCrypt = UrlCrypt::getInstance();

        $encrypted = $urlCrypt->encrypt($string, $key);

        $this->assertEquals($string, $urlCrypt->decrypt($encrypted, $key));
    }

    /**
     * @return array
     */
    public function encryptData()
    {
        return [
            'Base key' => ['Atrapalo', 'bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3'],
            'Medium key' => ['Atrapalo', 'bcb04b7e103a0cd8b5476305'],
            'UTF8 chars key' => ['Atrapalo', 'á#=()öñ*+^éíáá=()öñ*+^éá'],
            'Custom string key' => ['Atrapalo', 'AtrapaloKey'],
            'UTF8 chars and base key' => ['ȀȁȂȃȄȇȈȉȊȋȌȍȎȏȐȑȒȓȔȕȖȗȘșȚțȜȝȞȟ', 'AtrapaloKey'],
        ];
    }

    /**
     * @test
     */
    public function encryptionCustomTable()
    {
        $string = 'Atrapalo';
        $key = 'bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3';
        $urlCrypt = new UrlCrypt('pqrstAvwxyz5678901bcd2fgh3jklmn4');
        $encrypted = $urlCrypt->encrypt($string, $key);

        $this->assertEquals($string, $urlCrypt->decrypt($encrypted, $key));
    }

    /**
     * @test
     */
    public function encryptionCustomTableWithInstance()
    {
        $string = 'Atrapalo';
        $key = 'bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3';
        $urlCrypt = UrlCrypt::getInstance('pqrstAvwxyz5678901bcd2fgh3jklmn4');
        $encrypted = $urlCrypt->encrypt($string, $key);

        $this->assertEquals($string, $urlCrypt->decrypt($encrypted, $key));
    }

    /**
     * @test
     */
    public function failEncryptionWhitDifferentKeys()
    {
        $string = 'Atrapalo';
        $key = 'bcb04b7e103a0cd8b54763051cef08bc55abe029fdebae5e1d417e2ffb2a00a3';
        $key2 = 'c55abe029fdebae5e1d417e2ffb2a00a3bcb04b7e103a0cd8b54763051cef08b';

        $encrypted = $this->urlCrypt->encrypt($string, $key);

        $this->assertNotEquals($string, $this->urlCrypt->decrypt($encrypted, $key2));
    }

    /**
     * @param string $string
     * @return string
     */
    private function encodeAndDecode($string)
    {
        return $this->urlCrypt->decode($this->urlCrypt->encode($string));
    }
}
