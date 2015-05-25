<?php
/*
 * =========================================================================== *
 *  This file is part of IdPRef - IdP de Referencia para SIR 2 basado en
 *  SimpleSAMLPHP v1.13.1
 * =========================================================================== *
 * 
 * Copyright (C) 2014 - 2015 by the Spanish Research and Academic Network.
 * This code was developed by Auditoria y Consultoría de Privacidad y Seguridad
 * (PRiSE http://www.prise.es) for the RedIRIS SIR service (SIR: 
 * http://www.rediris.es/sir)
 *
 * *****************************************************************************
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 * ************************************************************************** */

/**
 * Base class for SAML 2 bindings.
 * 
 * @package    IdPRef\vendor\samls\src\SAML2
 * @author     "PRiSE [Auditoria y Consultoria de privacidad y Seguridad, S.L.]"
 * @copyright  Copyright (C) 2014 - 2015 by the Spanish Research and Academic
 *             Network
 * @license    http://www.apache.org/licenses/LICENSE-2.0  Apache License 2.0
 * @version    0.3-Sprint3-R57
 */
abstract class SAML2_Binding
{
    /**
     * The destination of messages.
     *
     * This can be NULL, in which case the destination in the message is used.
     */
    protected $destination;

    /**
     * Retrieve a binding with the given URN.
     *
     * Will throw an exception if it is unable to locate the binding.
     *
     * @param  string        $urn The URN of the binding.
     * @return SAML2_Binding The binding.
     * @throws Exception
     */
    public static function getBinding($urn)
    {
        assert('is_string($urn)');

        switch ($urn) {
            case SAML2_Const::BINDING_HTTP_POST:
                return new SAML2_HTTPPost();
            case SAML2_Const::BINDING_HTTP_REDIRECT:
                return new SAML2_HTTPRedirect();
            case SAML2_Const::BINDING_HTTP_ARTIFACT:
                return new SAML2_HTTPArtifact();
            case SAML2_Const::BINDING_HOK_SSO:
                return new SAML2_HTTPPost();
            case SAML2_Const::BINDING_PAOS:
                return new SAML2_PAOS();
            default:
                throw new Exception('Unsupported binding: ' . var_export($urn, TRUE));
        }
    }

    /**
     * Guess the current binding.
     *
     * This function guesses the current binding and creates an instance
     * of SAML2_Binding matching that binding.
     *
     * An exception will be thrown if it is unable to guess the binding.
     *
     * @return SAML2_Binding The binding.
     * @throws Exception
     */
    public static function getCurrentBinding()
    {
        switch ($_SERVER['REQUEST_METHOD']) {
            case 'GET':
                if (array_key_exists('SAMLRequest', $_GET) || array_key_exists('SAMLResponse', $_GET)) {
                    return new SAML2_HTTPRedirect();
                } elseif (array_key_exists('SAMLart', $_GET)) {
                    return new SAML2_HTTPArtifact();
                }
                break;

            case 'POST':
                if (isset($_SERVER['CONTENT_TYPE'])) {
                    $contentType = $_SERVER['CONTENT_TYPE'];
                    $contentType = explode(';', $contentType);
                    $contentType = $contentType[0]; /* Remove charset. */
                } else {
                    $contentType = NULL;
                }
                if (array_key_exists('SAMLRequest', $_POST) || array_key_exists('SAMLResponse', $_POST)) {
                    return new SAML2_HTTPPost();
                } elseif (array_key_exists('SAMLart', $_POST)) {
                    return new SAML2_HTTPArtifact();
                } elseif ($contentType === 'text/xml') {
                    return new SAML2_SOAP();
                } elseif ($contentType === "application/x-www-form-urlencoded") {
                    return new SAML2_PAOS();
                }
                break;
        }

        $logger = SAML2_Utils::getContainer()->getLogger();
        $logger->warning('Unable to find the SAML 2 binding used for this request.');
        $logger->warning('Request method: ' . var_export($_SERVER['REQUEST_METHOD'], TRUE));
        if (!empty($_GET)) {
            $logger->warning("GET parameters: '" . implode("', '", array_map('addslashes', array_keys($_GET))) . "'");
        }
        if (!empty($_POST)) {
            $logger->warning("POST parameters: '" . implode("', '", array_map('addslashes', array_keys($_POST))) . "'");
        }
        if (isset($_SERVER['CONTENT_TYPE'])) {
            $logger->warning('Content-Type: ' . var_export($_SERVER['CONTENT_TYPE'], TRUE));
        }

        throw new Exception('Unable to find the current binding.');
    }

    /**
     * Retrieve the destination of a message.
     *
     * @return string|NULL $destination  The destination the message will be delivered to.
     */
    public function getDestination()
    {
        return $this->destination;
    }

    /**
     * Override the destination of a message.
     *
     * Set to NULL to use the destination set in the message.
     *
     * @param string|NULL $destination The destination the message should be delivered to.
     */
    public function setDestination($destination)
    {
        assert('is_string($destination) || is_null($destination)');

        $this->destination = $destination;
    }

    /**
     * Send a SAML 2 message.
     *
     * This function will send a message using the specified binding.
     * The message will be delivered to the destination set in the message.
     *
     * @param SAML2_Message $message The message which should be sent.
     */
    abstract public function send(SAML2_Message $message);

    /**
     * Receive a SAML 2 message.
     *
     * This function will extract the message from the current request.
     * An exception will be thrown if we are unable to process the message.
     *
     * @return SAML2_Message The received message.
     */
    abstract public function receive();

}
